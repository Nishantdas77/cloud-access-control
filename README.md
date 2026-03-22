# ☁ CloudVault — Cloud Access Control & Key Management
### Group Project Demo | Cloud Computing Course

---

## 🚀 Quick Start (3 commands)

```bash
# 1. Install dependencies
pip install flask cryptography

# 2. Run the server
python app.py

# 3. Open in browser
# http://localhost:5000
```

---

## 👥 Demo Users

| Username | Password   | Role        | Department | Clearance    |
|----------|------------|-------------|------------|--------------|
| alice    | alice123   | **admin**   | IT         | top-secret   |
| bob      | bob123     | developer   | Eng        | confidential |
| carol    | carol123   | viewer      | HR         | public       |
| eve      | eve123     | guest       | Ext        | none         |

---

## 🎯 Features Implemented

### 1. Attribute-Based Access Control (ABAC)
- Every resource has a **policy** with 3 attributes: minimum role, clearance level, and allowed departments
- All 3 attributes must match for access to be granted
- Try: login as `eve` and try to access Secret Files → **DENIED**
- Try: login as `alice` (admin) → can access everything

### 2. Key Management Service (KMS)
- Generate cryptographic keys (AES-256 or Fernet)
- **Rotate** a key → old key becomes inactive, new key generated
- **Revoke** a key → data encrypted with it becomes permanently inaccessible
- Only admin/developer can generate; only admin can revoke

### 3. Encrypt & Decrypt
- Encrypt any text with a managed key and bind it to a resource
- Decryption requires passing the ABAC check for that resource
- If the encryption key is **revoked**, decryption fails even if you have access rights
- Demonstrates: access control + key lifecycle together

### 4. Audit Log
- Every login, access check, encrypt, decrypt, key operation is logged
- Only **admin** can view the audit log (try as carol → denied)
- Shows: user, role, action, resource, result, timestamp

### 5. Policy Viewer
- Visual display of all ABAC policies, role hierarchy, and clearance levels
- Great for explaining the system to your professor

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Flask Web App                      │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────┐ │
│  │  Auth    │  │   ABAC   │  │  Key Management    │ │
│  │  Module  │  │  Engine  │  │  Service (KMS)     │ │
│  └──────────┘  └──────────┘  └────────────────────┘ │
│                                                      │
│  ┌──────────────────┐  ┌─────────────────────────┐  │
│  │  Crypto Engine   │  │     Audit Logger        │  │
│  │  AES-256/Fernet  │  │  (all events recorded)  │  │
│  └──────────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## 📡 REST API Endpoints

| Method | Endpoint                  | Description              |
|--------|---------------------------|--------------------------|
| POST   | /api/login                | Authenticate user        |
| GET    | /api/access/{resource}    | ABAC access check        |
| GET    | /api/keys                 | List keys                |
| POST   | /api/keys/generate        | Generate new key         |
| POST   | /api/keys/{id}/rotate     | Rotate a key             |
| POST   | /api/keys/{id}/revoke     | Revoke a key             |
| POST   | /api/encrypt              | Encrypt data             |
| POST   | /api/decrypt              | Decrypt blob             |
| GET    | /api/audit                | View audit log (admin)   |
| GET    | /api/policy               | View ABAC policies       |

---

## 📖 Concepts Demonstrated

- **ABAC vs RBAC**: Role is just *one* of three attributes evaluated
- **Key Lifecycle**: Generate → Active → Rotated/Revoked
- **Crypto at Rest**: Data is always stored encrypted; plaintext only shown after auth
- **Least Privilege**: Each role gets minimum necessary access
- **Non-repudiation**: Audit log cannot be modified; records all events
- **Defense in Depth**: Both ABAC check AND key status checked during decrypt
