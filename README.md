<div align="center">

# 🔏 Digital Signature Demonstration System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Web%20Framework-green.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3D-Yes-brightgreen.svg)]()

*A secure, interactive web-based demonstration system for digital signatures, RSA-PSS cryptography, and message integrity verification.*

</div>

---

## ✨ Key Features

- 🔑 **RSA Key Generation:** Generates robust RSA-2048 / RSA-3072 public and private key pairs.
- 🔒 **Encrypted Storage:** Password-encrypted private keys stored securely locally.
- 📝 **Message Signing & Verification:** Sign text messages using SHA-256 and RSA-PSS with live verification.
- 📂 **File Support:** Secure file signing and verification for PDF, TXT, DOCX, PNG, and JPG formats (up to 10 MB).
- 🛡️ **Tamper Detection:** Live demonstration showing how modified messages or files instantly trigger an **INVALID** status.
- 📜 **X.509 Certificates:** Self-signed demo certificate generation and inspection.
- 📊 **Audit Logs:** SQLite-backed audit trails and activity tracking counters.

---

## 🚀 Getting Started

### Prerequisites
Make sure you have **Python 3.8+** installed on your system.

### Installation & Setup

#### For macOS / Linux:
```bash
git clone [https://github.com/Sahil-sh378/Digital_Signature_System.git](https://github.com/Sahil-sh378/Digital_Signature_System.git)
cd Digital_Signature_System
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py