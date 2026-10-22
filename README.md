# CyberDesk — Parrot OS Desktop-Style Cybersecurity Toolkit

A local-first defensive security learning project built with Python 3.13, Flask, HTML, CSS, and JavaScript. It runs in a browser tab with a desktop-style dashboard.

## Features
- **System overview:** local hostname, platform, Python version and local IP.
- **File integrity:** calculate SHA-256 for a chosen file (maximum 8 MB). The file is processed in memory and not saved by the app.
- **Password audit:** basic local strength heuristic. The password is not stored or logged. Use a made-up sample, not a real password.
- **Log analyzer:** flags common security phrases in pasted text (maximum 1 MB).
- **Text report:** exports generic system facts only, not passwords or submitted logs.
- **Local-only server:** binds to `127.0.0.1`, not exposed to other devices.

## Folder structure
```text
parrot_cyberdesk_web/
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   └── index.html
└── static/
    ├── style.css
    └── app.js
```

## Setup on Parrot OS (Python 3.13.5)

Open a terminal in this folder:

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

Then open this address in your browser:

`http://127.0.0.1:5000`

To stop the server, return to the terminal and press `Ctrl+C`.

### If venv creation fails
On Debian/Parrot-based systems, install the venv package if your package manager offers it:

```bash
sudo apt update
sudo apt install python3-venv
```

Then repeat the venv commands. Do not use `sudo pip install`.

## Safety and limitations
- Intended for learning and defensive checks on your own system or systems you are authorized to inspect.
- This is not a full security scanner and does not test external hosts.
- Password scoring is a simple heuristic and is not a password-cracking test.
- Log matches are keyword hints and can produce false positives or miss issues.
- Do not paste secrets, private customer logs, or production credentials into a demo tool.
