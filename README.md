# Secure Examination-Paper Exchange (Python, `cryptography` library)

## Files
| Path | Purpose |
|---|---|
| `secure_exam.py` | Library + CLI: `keygen`, `encrypt`, `decrypt` |
| `simulate.py` | Two-party simulation (sender/recipient folders) + all required tests |
| `make_diagram.py`, `sequence_diagram.svg` | Sequence-of-events diagram |
| `sender/input/exam_paper.txt` | Sample input file |
| `channel/*.pkg` | Encrypted packages (valid, second encryption, tampered, forged) |
| `recipient/recovered_exam_paper.txt` | File recovered by the coordinator |
| `sender/`, `recipient/`, `attacker/` `keys/` | RSA-4096 keys (private keys passphrase-encrypted, mode 0600) |
| `test_results.txt` | Captured output of the full test run (13/13 PASS) |

## Run
```
pip install cryptography
python simulate.py                   # full simulation + tests
# or manual use
export EXAM_KEY_PASSPHRASE=...       # or type when prompted
python secure_exam.py keygen  --name faculty --out sender/keys
python secure_exam.py encrypt --in paper.pdf --sender-id faculty --recipient-id coordinator \
    --sender-key sender/keys/faculty_private.pem --recipient-pub sender/trusted/coordinator_public.pem --out channel/paper.pkg
python secure_exam.py decrypt --in channel/paper.pkg --recipient-key recipient/keys/coordinator_private.pem \
    --sender-pub recipient/trusted/faculty_public.pem --recipient-id coordinator --out-dir recipient/inbox
```

## Package format (JSON, base64 fields)
`metadata` (version, package_id, filename, sender_id, recipient_id, UTC time, size, algorithms),
`encrypted_session_key`, `nonce`, `ciphertext`, `tag`, `signature`.

## Sequence of events
```mermaid
sequenceDiagram
    participant S as Faculty (Sender)
    participant C as Untrusted Channel / Attacker
    participant R as Coordinator (Recipient)
    Note over S,R: Setup: RSA-4096 pairs; public keys exchanged over a TRUSTED channel
    S->>S: 1. Random AES-256 key K + fresh 96-bit nonce
    S->>S: 2. (ciphertext, tag) = AES-GCM(K, nonce, paper, AAD = metadata)
    S->>S: 3. EK = RSA-OAEP-SHA256(recipient public key, K)
    S->>S: 4. sig = RSA-PSS-SHA256(sender private key, whole package)
    S->>C: package {metadata, EK, nonce, ciphertext, tag, sig}
    Note over C: attacker may read / modify / replace / drop
    C->>R: package (possibly altered)
    R->>R: 5. Verify sig with TRUSTED sender public key
    alt signature invalid
        R-->>R: REJECT (nothing decrypted or written)
    end
    R->>R: 6. K = RSA-OAEP-decrypt(recipient private key, EK)
    alt wrong key
        R-->>R: REJECT
    end
    R->>R: 7. AES-GCM decrypt, verify tag (ciphertext + metadata)
    alt tag invalid
        R-->>R: REJECT
    end
    R->>R: 8. All checks passed -> write plaintext to inbox
```
(The same diagram is in `sequence_diagram.svg`.)

## How the three security goals are achieved
**Confidentiality.** The paper is encrypted with AES-256-GCM under a fresh random session key and a fresh
96-bit nonce per package. The session key is encrypted with the coordinator's RSA-4096 public key using
OAEP/SHA-256, so only the holder of the coordinator's private key can recover it. An eavesdropper sees only
ciphertext; because key and nonce are new each time, encrypting the same paper twice gives completely different
packages (Test 5), hiding repetition.

**Integrity.** Two independent layers. (1) The sender's RSA-PSS signature covers the *entire* package: metadata,
encrypted key, nonce, ciphertext and tag, so changing any single bit anywhere is detected (Tests 2a-2h).
(2) GCM's authentication tag covers the ciphertext and, via AAD, the metadata, so the data is checked again
after the key is recovered. Verification happens first and plaintext is written to disk only after signature,
key unwrap and tag all succeed; any failure raises a single `VerificationError` and nothing is released.

**Sender authentication (and non-repudiation).** Only the faculty member's private key can produce a signature
that verifies under the faculty public key the coordinator holds from the trusted exchange. An attacker who
replaces the package with a fake of their own, even a correctly formed one encrypted for the coordinator,
cannot sign it as the faculty (Tests 4 and 6). Because `recipient_id` is signed, a valid package cannot be
silently redirected to a different recipient identity.

## Design notes and limitations
* The tag is stored as its own field (cryptography's `AESGCM` appends it to the ciphertext; the code splits and rejoins it).
* Sign-then-verify-first order means tampering is normally reported as "signature invalid"; the GCM check is the
  defence-in-depth layer (e.g. a compromised signer or a coding mistake).
* Not covered: replay of an old valid package (could add a timestamp window or a recipient-side package_id log),
  loss of a private key or passphrase, and compromise of the trusted public-key exchange itself.
* The demo passphrase in `simulate.py` is hard-coded for repeatability only; the CLI reads it from a prompt or
  the `EXAM_KEY_PASSPHRASE` environment variable.
