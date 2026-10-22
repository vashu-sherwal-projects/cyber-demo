from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
from datetime import datetime
import hashlib
import re
import socket
import platform
import os
import io

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8 MB uploads only
APP_DIR = Path(__file__).resolve().parent

def password_audit(password: str) -> dict:
    """Simple local password-strength estimate; never stores the password."""
    checks = {
        "length_12": len(password) >= 12,
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "number": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    score = sum(checks.values())
    if len(password) < 8:
        label, advice = "Weak", "Use at least 12 characters; avoid names and reused passwords."
    elif score <= 2:
        label, advice = "Needs improvement", "Add mixed case, numbers, symbols, and more length."
    elif score <= 4:
        label, advice = "Good", "Consider using a longer unique passphrase."
    else:
        label, advice = "Strong", "Use it only for one account and store it in a password manager."
    return {"score": score, "out_of": 5, "label": label, "checks": checks, "advice": advice}

LOG_PATTERNS = [
    ("Failed login", re.compile(r"failed password|authentication failure|login failed|invalid user", re.I)),
    ("Permission denied", re.compile(r"permission denied|access denied", re.I)),
    ("Privilege event", re.compile(r"sudo:|su:|privilege", re.I)),
    ("Possible connection issue", re.compile(r"connection refused|too many connections|connection timed out", re.I)),
    ("Security keyword", re.compile(r"malware|trojan|ransomware|backdoor", re.I)),
]

def analyze_log(text: str):
    findings = []
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        for label, pattern in LOG_PATTERNS:
            if pattern.search(line):
                findings.append({"line": number, "type": label, "text": line[:500]})
                break
    return {"total_lines": len(lines), "findings": findings, "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/api/system")
def system_info():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except OSError:
        hostname, local_ip = socket.gethostname(), "Unavailable"
    return jsonify({
        "app": "CyberDesk",
        "mode": "Local defensive tools",
        "hostname": hostname,
        "local_ip": local_ip,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })

@app.post("/api/hash")
def hash_file():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "Choose a file first."}), 400
    digest = hashlib.sha256()
    size = 0
    # Read in chunks; the upload is processed in memory and is not saved to disk.
    while True:
        chunk = uploaded.stream.read(64 * 1024)
        if not chunk:
            break
        size += len(chunk)
        digest.update(chunk)
    return jsonify({
        "filename": Path(uploaded.filename).name,
        "size_bytes": size,
        "sha256": digest.hexdigest(),
        "note": "Processed locally in memory; file was not saved by CyberDesk."
    })

@app.post("/api/password")
def password_check():
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))
    if not password:
        return jsonify({"error": "Enter a password to check."}), 400
    result = password_audit(password)
    # Do not log or retain password. Response only includes the audit.
    return jsonify(result)

@app.post("/api/logs")
def logs_check():
    data = request.get_json(silent=True) or {}
    text = str(data.get("text", ""))
    if not text.strip():
        return jsonify({"error": "Paste log text or upload a text file."}), 400
    if len(text) > 1_000_000:
        return jsonify({"error": "Log text is too large (limit: 1 MB)."}), 413
    return jsonify(analyze_log(text))

@app.get("/api/report")
def report():
    # Export only generic local system facts, not passwords or log contents.
    info = {
        "CyberDesk report": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Platform": platform.platform(),
        "Python": platform.python_version(),
        "Hostname": socket.gethostname(),
        "Notice": "This report excludes passwords and submitted log contents.",
    }
    content = "\n".join(f"{k}: {v}" for k, v in info.items()) + "\n"
    return send_file(io.BytesIO(content.encode()), mimetype="text/plain",
                     as_attachment=True, download_name="cyberdesk-report.txt")

@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "File too large. Maximum upload size is 8 MB."}), 413

if __name__ == "__main__":
    # Localhost only: not exposed to the network.
    app.run(host="127.0.0.1", port=5000, debug=False)
