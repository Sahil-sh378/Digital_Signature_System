# Digital Signature Demonstration System

## Features
- RSA-2048 / RSA-3072 public/private key generation
- Password-encrypted private key stored locally
- Public key, encrypted private key and demo certificate downloads
- SHA-256 message hashing
- RSA-PSS digital signing and verification
- Message tampering demonstration
- File signing and verification for PDF, TXT, DOCX, PNG and JPG (10 MB max)
- Self-signed X.509 demo certificate
- SQLite audit logs and activity counters

## Run on macOS
```bash
cd Digital_Signature_System_Full
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```
Open http://127.0.0.1:5000

## Windows
```powershell
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
py app.py
```

## Demonstration
1. Generate keys with a passphrase of 8+ characters.
2. Copy or download the public key. The private key is encrypted and never displayed.
3. Enter a message and passphrase; click Sign Message.
4. Verify the original message: it should be VALID.
5. Change one character in the modified-message box and verify it with the same signature: it should be INVALID.
6. Select a file, sign it, then verify the unchanged file.
7. Modify the file and verify again: it should be INVALID.
8. View the certificate and audit logs.

## Security limitations
Educational local demo only. The certificate is self-signed and is not trusted by a public CA. Audit logs are ordinary local SQLite records, not tamper-proof. Do not expose Flask debug server to the internet. Production use requires HTTPS, authentication, CSRF protection, rate limiting, hardened key storage, trusted certificate issuance and protected audit logging.
