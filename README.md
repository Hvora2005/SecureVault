# SecureVault — Cryptography as a Security Tool

SecureVault is an offline-first academic security console demonstrating file protection, user authentication, integrity checking, signatures, secure random generation, and local audit trails. It uses React/Vite, Python/FastAPI, and local SQLite.

> For classroom demonstration and learning. MD5 and DES are included only to explain legacy cryptography. The local session token and one-pass file overwrite illustrate concepts and are not a hardened production service.

## Objectives

- Explain how OS access control, file storage, authentication, integrity, and audit logging support security.
- Apply AES-256-GCM to vault contents using a password-derived key and unique salt/nonce.
- Demonstrate salted scrypt password hashing, SHA digests, and RSA-PSS signatures.
- Provide a local project classmates can launch with a single Windows batch file.

## Features

- Local registration/login and password change; salted scrypt password verifiers.
- AES-256-GCM encryption/decryption with tamper detection and clear wrong-password errors.
- Vault upload, search, rename, download, confirmed deletion, and drag/drop upload.
- SHA-256, SHA-512, educational MD5 text/file hashing, and integrity comparison.
- RSA-2048 PSS signing and verification; local audit logs and CSV export.
- Secure password generation, searchable event history, dashboard, theme settings.
- Algorithm reference for AES, RSA, SHA-256, SHA-512, MD5, DES, and Blowfish.
- Demo workspace button creates `demo` / `VaultDemo2026!`, sample files, and activity.
- Local ZIP backup and restore (with path-safe extraction and duplicate-name handling), plus vault clearing.

## Technology

React 18, Vite, JavaScript, CSS, Lucide React, Recharts; Python 3.10+, FastAPI, Uvicorn, cryptography, python-multipart, SQLite, hashlib/csv/secrets.

## Structure

```text
SecureVault/
├── backend/                 FastAPI API and local persistence
│   ├── main.py
│   ├── requirements.txt
│   └── data/                Created at first run (ignored by Git)
├── frontend/                React + Vite interface
│   ├── src/main.jsx
│   ├── src/style.css
│   └── package.json
├── demo_files/              Optional presentation files
├── start_project.bat        Setup, start services, open browser
├── start_backend.bat
├── start_frontend.bat
├── INSTALLATION_GUIDE.md
└── PRESENTATION_GUIDE.md
```

## Run on Windows

Install Python 3.10+ and Node.js 18+ once, then double-click `start_project.bat`. First run downloads pinned packages; later launches work offline. It opens `http://127.0.0.1:5173`. Click **Launch the demo workspace** for the prepared walkthrough.

See [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md) for manual steps and [PRESENTATION_GUIDE.md](PRESENTATION_GUIDE.md) for a five-minute walkthrough.

## Screenshots

Add captures from the running application before submission:

| Dashboard | Vault | Cryptography tools |
|---|---|---|
| `docs/dashboard.png` | `docs/vault.png` | `docs/tools.png` |

## Verification

After installing the backend requirements, run `cd backend` followed by `.venv\Scripts\python.exe -m unittest discover -s tests -v`. The API suite covers registration/login, dashboard access control, empty and multi-megabyte files, AES wrong-password and corruption handling, text/file hashes, RSA signature tampering, duplicate names, rename, secure delete, CSV export, password changes, and generated passwords. Run `cd frontend` then `npm run build` to produce the optimized static bundle.

## Security notes

Passwords use individual random salts and scrypt. File keys are derived using scrypt and unique random salts; AES-GCM provides confidentiality and tamper detection. RSA private keys are stored locally without a passphrase for the classroom demo. The API binds to loopback. The local token is a teaching convenience, not hardened session management. Overwrite-before-unlink cannot guarantee physical erasure on SSDs, journaled filesystems, or copy-on-write storage.

## Future scope

Cloud backup, biometric authentication, OTP, role-based access, hardened multi-user support, and network file encryption. Extensions need threat modeling and key management.

## Author

**Student:** Add your name and roll number before submission.  
**Course:** Operating Systems — Third Year  
**Project:** SecureVault — Cryptography as a Security Tool
