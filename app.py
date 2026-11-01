import os, base64, hashlib, sqlite3
from pathlib import Path
from datetime import datetime, timedelta, timezone

from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID

BASE = Path(__file__).resolve().parent
KEYS = BASE / "keys"
KEYS.mkdir(exist_ok=True)
PRIVATE = KEYS / "private_key_encrypted.pem"
PUBLIC = KEYS / "public_key.pem"
CERT = KEYS / "demo_certificate.pem"
DB = BASE / "audit.db"
ALLOWED = {"pdf", "txt", "docx", "png", "jpg", "jpeg"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

def connect_db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with connect_db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT, status TEXT, details TEXT, created_at TEXT
        )""")

def log(event, status="SUCCESS", details=""):
    with connect_db() as con:
        con.execute("INSERT INTO audit(event,status,details,created_at) VALUES(?,?,?,?)",
                    (event, status, str(details)[:200], datetime.now(timezone.utc).isoformat()))

def error(message, code=400):
    return jsonify(success=False, error=message), code

def get_private(passphrase):
    if not PRIVATE.exists():
        raise ValueError("Generate an RSA key pair first.")
    if not passphrase:
        raise ValueError("Enter the private-key passphrase.")
    return serialization.load_pem_private_key(
        PRIVATE.read_bytes(), password=passphrase.encode()
    )

def get_public(pem=None):
    if pem:
        return serialization.load_pem_public_key(pem.encode())
    if not PUBLIC.exists():
        raise ValueError("Generate an RSA key pair first.")
    return serialization.load_pem_public_key(PUBLIC.read_bytes())

def sign_data(raw, key):
    return key.sign(raw, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ), hashes.SHA256())

def verify_data(raw, signature, key):
    key.verify(signature, raw, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ), hashes.SHA256())

def make_certificate(private_key, public_key):
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Digital Signature Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Local Demo Signer")
    ])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(public_key).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256()))
    CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

@app.get("/")
def home():
    return render_template("index.html")

@app.post("/api/keys")
def generate_keys():
    data = request.get_json() or {}
    password = data.get("passphrase", "")
    size = data.get("key_size", 2048)
    if len(password) < 8:
        return error("Passphrase must contain at least 8 characters.")
    if size not in (2048, 3072):
        return error("Select RSA-2048 or RSA-3072.")
    try:
        private = rsa.generate_private_key(public_exponent=65537, key_size=size)
        public = private.public_key()
        private_pem = private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password.encode()))
        public_pem = public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        PRIVATE.write_bytes(private_pem)
        os.chmod(PRIVATE, 0o600)
        PUBLIC.write_bytes(public_pem)
        make_certificate(private, public)
        fingerprint = hashlib.sha256(public_pem).hexdigest()
        log("RSA key pair generated", "SUCCESS", f"RSA-{size}")
        return jsonify(success=True, public_key=public_pem.decode(),
                       fingerprint=fingerprint, key_size=size, exponent=65537)
    except Exception as exc:
        log("Key generation", "FAILED", type(exc).__name__)
        return error("Key generation failed: " + str(exc), 500)

@app.get("/download/<kind>")
def download(kind):
    choices = {"public": (PUBLIC, "public_key.pem"),
               "private": (PRIVATE, "private_key_encrypted.pem"),
               "certificate": (CERT, "demo_certificate.pem")}
    if kind not in choices:
        return error("Unknown download.", 404)
    path, name = choices[kind]
    if not path.exists():
        return error("Generate keys first.", 404)
    return send_file(path, as_attachment=True, download_name=name)

@app.post("/api/sign")
def sign_message():
    data = request.get_json() or {}
    message, password = data.get("message", ""), data.get("passphrase", "")
    if not isinstance(message, str) or not message.strip():
        return error("Enter a message.")
    try:
        raw = message.encode("utf-8")
        signature = sign_data(raw, get_private(password))
        digest = hashlib.sha256(raw).hexdigest()
        log("Message signed", "SUCCESS", "SHA-256 " + digest[:16])
        return jsonify(success=True, hash=digest,
                       signature=base64.b64encode(signature).decode())
    except Exception:
        log("Message signing", "FAILED", "Passphrase/key/signing error")
        return error("Signing failed. Check your passphrase and generated keys.")

@app.post("/api/verify")
def verify_message():
    data = request.get_json() or {}
    message, signature_text = data.get("message", ""), data.get("signature", "")
    try:
        if not message:
            return error("Enter the message to verify.")
        signature = base64.b64decode(signature_text, validate=True)
        verify_data(message.encode("utf-8"), signature, get_public(data.get("public_key") or None))
        log("Signature verification", "VALID", "Message verified")
        return jsonify(success=True, valid=True, message="VALID — signature matches this message.")
    except InvalidSignature:
        log("Signature verification", "INVALID", "Signature mismatch")
        return jsonify(success=True, valid=False, message="INVALID — message, signature, or public key does not match.")
    except Exception as exc:
        log("Signature verification", "ERROR", type(exc).__name__)
        return error(str(exc))

@app.post("/api/file/sign")
def sign_file():
    f = request.files.get("file")
    password = request.form.get("passphrase", "")
    if not f or not f.filename:
        return error("Choose a file.")
    filename = secure_filename(f.filename)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED:
        return error("Allowed: PDF, TXT, DOCX, PNG, JPG.")
    raw = f.read()
    try:
        signature = sign_data(raw, get_private(password))
        digest = hashlib.sha256(raw).hexdigest()
        log("File signed", "SUCCESS", filename)
        return jsonify(success=True, filename=filename, hash=digest,
                       signature=base64.b64encode(signature).decode())
    except Exception:
        log("File signing", "FAILED", filename)
        return error("File signing failed. Check your passphrase and keys.")

@app.post("/api/file/verify")
def verify_file():
    f = request.files.get("file")
    signature_text = request.form.get("signature", "")
    public_pem = request.form.get("public_key", "").strip() or None
    if not f or not f.filename:
        return error("Choose a file.")
    raw = f.read()
    try:
        signature = base64.b64decode(signature_text, validate=True)
        verify_data(raw, signature, get_public(public_pem))
        log("File verification", "VALID", secure_filename(f.filename))
        return jsonify(success=True, valid=True, hash=hashlib.sha256(raw).hexdigest(),
                       message="VALID — file contents match the signature.")
    except InvalidSignature:
        log("File verification", "INVALID", secure_filename(f.filename))
        return jsonify(success=True, valid=False, hash=hashlib.sha256(raw).hexdigest(),
                       message="INVALID — file changed or signature/key is incorrect.")
    except Exception as exc:
        return error(str(exc))

@app.get("/api/certificate")
def certificate_info():
    if not CERT.exists():
        return error("Generate keys first.")
    cert = x509.load_pem_x509_certificate(CERT.read_bytes())
    return jsonify(success=True, subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(), serial=str(cert.serial_number),
        valid_from=cert.not_valid_before_utc.isoformat(),
        valid_until=cert.not_valid_after_utc.isoformat(),
        fingerprint=cert.fingerprint(hashes.SHA256()).hex())

@app.get("/api/audit")
def audit():
    with connect_db() as con:
        rows = con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100").fetchall()
        counts = con.execute("""SELECT COUNT(*) total,
            SUM(CASE WHEN event LIKE '%signed%' THEN 1 ELSE 0 END) signed,
            SUM(CASE WHEN status='VALID' THEN 1 ELSE 0 END) valid,
            SUM(CASE WHEN status='INVALID' THEN 1 ELSE 0 END) invalid FROM audit""").fetchone()
    return jsonify(success=True, stats={k: counts[k] or 0 for k in counts.keys()},
        logs=[dict(r) for r in rows])

@app.errorhandler(413)
def too_large(_):
    return error("Maximum upload size is 10 MB.", 413)

if __name__ == "__main__":
    init_db()
    print("Open http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
