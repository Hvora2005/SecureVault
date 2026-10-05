# SecureVault Presentation Guide

## Five-minute walkthrough

### 0:00–0:35 — Problem and OS context

“An operating system stores files, controls access, and records actions. Cryptography can protect data even when storage is exposed. SecureVault is a local lab showing encryption, authentication, integrity, signatures, and audit history.”

### 0:35–1:00 — Launch the demo

Start `start_project.bat` before class. Click **Launch the demo workspace** when the browser opens. If needed, the demo login is `demo` / `VaultDemo2026!`.

### 1:00–1:40 — Dashboard and vault

Point out workspace totals, security posture, and recent events. Open **Vault**; metadata is indexed in SQLite while bytes remain in the local backend data folder. Upload a small text file and show search or rename.

### 1:40–2:30 — AES encryption

Choose **Encrypt file**, select a vault file, and enter a demonstration passphrase. Scrypt derives a 256-bit key using a fresh salt. AES-GCM encrypts and authenticates using a fresh nonce. Attempt decryption with a wrong password, then retry with the correct one.

### 2:30–3:10 — Hashes and integrity

Generate SHA-256 for a text. Explain that a hash is a one-way fingerprint, not encryption. MD5 appears only as an unsafe legacy example. **Integrity checker** compares a current file digest to the known original.

### 3:10–3:50 — Digital signatures

Use **Digital signature** to sign an unencrypted file with RSA-PSS and verify it. The private key signs; the public key checks the signer and detects changes. This demonstrates authentication, integrity, and evidence supporting non-repudiation.

### 3:50–4:25 — Passwords and audit

Show **Password generator**, then **Activity logs** and CSV export. Account password verifiers use a unique salt and scrypt; audit entries record security operations.

### 4:25–5:00 — Close

Show **Algorithms** and **Settings**. Summarize local file storage, access control, encryption at rest, integrity verification, key storage, and audit logging. The API binds to loopback and needs no cloud account.

## Demo checklist

- Run once before presenting to install packages and catch port conflicts.
- Keep a small `.txt` file ready; do not use confidential data or huge files.
- Load Demo Mode first so the dashboard and logs are populated.
- Demo password: `VaultDemo2026!`.
- Runtime works offline after packages have been installed.

## Operating Systems concepts

- **Protection/access control:** the authenticated user can access only their own indexed entries.
- **Persistence:** SQLite indexes metadata; files and keys are stored under the backend data directory.
- **Least exposure:** loopback binding keeps the demo local to the computer.
- **Auditability:** activity records support accountability and incident review.
- **Deletion limits:** overwrite-before-unlink is illustrative; SSD wear-leveling, snapshots, journals, or copy-on-write may preserve physical blocks.

## Cryptography concepts

- **Confidentiality:** AES-256-GCM encrypts file data with a derived secret.
- **Key derivation:** scrypt increases password guessing cost; each file gets random salt material.
- **Authenticated encryption:** GCM detects wrong keys and changed ciphertext.
- **Integrity:** SHA-256/SHA-512 yield fixed-length fingerprints; they do not hide data.
- **Signatures:** RSA-PSS is verified with a public key and detects file changes.
- **Password storage:** scrypt with unique salts; plaintext passwords are not saved.
- **Legacy algorithms:** MD5 and DES are unsafe for protecting new data. Blowfish's 64-bit block size limits its use with large datasets.

## Likely viva questions

**1. Encryption versus hashing?** Encryption is reversible with a key and protects confidentiality. Hashing is one-way and creates a comparison fingerprint.

**2. Why AES-GCM?** AES is efficient symmetric encryption; GCM also authenticates data so tampering is detected.

**3. What is a salt?** Random input used with a password before derivation/hash. It prevents equal passwords from having equal stored results and defeats precomputed tables.

**4. Why scrypt?** It is memory-hard and slower than a general-purpose hash, raising the cost of guessing many passwords.

**5. What does a digital signature establish?** A valid signature shows the bytes match and the signer had the private key corresponding to the public verification key. It does not encrypt the file.

**6. Why is MD5 insecure?** Practical collisions exist, so different inputs can share an MD5 digest.

**7. What if the AES password is wrong?** The key differs and GCM authentication fails; unauthenticated plaintext is not written.

**8. Where are keys stored?** The file-encryption key is derived when needed, not saved. RSA keys are local in the backend data folder for this demo.

**9. Is overwrite-and-delete guaranteed?** No. SSD controllers, journals, snapshots, and copy-on-write may preserve old blocks. Cryptographic erasure can be more reliable if data was encrypted from the start.

**10. Does it require internet?** Only initial package installation. Runtime is local and offline.

## Limitation to disclose

This is a single-machine educational project. Production requires hardened sessions, encrypted private-key storage, rate limits, recovery planning, reviewed dependencies, encrypted backups, and a threat model.
