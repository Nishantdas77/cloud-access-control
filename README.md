# ☁ CloudVault

> Cloud Access Control & Key Management 

A local web app that simulates how real cloud platforms like AWS protect data using two simultaneous security layers: **Attribute-Based Access Control (ABAC)** and **AES-256 Key Management**.

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install flask cryptography

# Run
python app.py

# Open in browser
http://localhost:5000
```


---

## ✨ Features

- **🔐 Access Control** — ABAC checks role + department + clearance simultaneously
- **🔑 Key Management** — Generate, rotate, and revoke AES-256 keys
- **🔒 Encrypt / Decrypt** — Type text or upload a file to encrypt
- **📋 Audit Log** — Every event logged, admin-only access
- **📜 Policy Viewer** — See the full ABAC policy table

---

## 🏗 How It Works

Every decrypt request passes **two independent locks**:

```
User request
    │
    ├── Lock 1: ABAC check (role + dept + clearance)
    │       └── DENIED → blocked
    │
    └── Lock 2: Key status check (active / rotated / revoked)
            └── REVOKED → blocked

Both pass → file decrypted ✓
```

This is the same security model used by **AWS IAM + KMS** in production.

---

## 📁 Project Structure

```
cloud-access-demo/
├── app.py              # Flask backend — all logic here
├── requirements.txt    # flask, cryptography
└── templates/
    └── index.html      # Single-page frontend
```

---

## 🔑 Key Concepts

| Term | What it means |
|------|--------------|
| **ABAC** | Access based on 3 attributes — not just role |
| **AES-256** | Encryption algorithm used by banks & governments |
| **Rotate** | Retire old key, create new one — old files still readable |
| **Revoke** | Permanently block a key — no one can decrypt, ever |
| **Audit Log** | Tamper-evident record of every access event |

---

## 🛠 Tech Stack

`Python` · `Flask` · `AES-256`  · `HTML/CSS/JS`

---

*Built for Cloud Computing course (Term Project) — IIT Kharagpur*