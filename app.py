from flask import Flask, request, jsonify, render_template, session
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os, json, base64, secrets, hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ─── In-memory state ───────────────────────────────────────────────────────────

USERS = {
    "Nishant":   {"password": "nishant123",   "role": "admin",     "department": "IT",  "clearance": "top-secret"},
    "Srijib":     {"password": "srijib123",     "role": "developer", "department": "Eng", "clearance": "confidential"},
    "Sudipa":   {"password": "sudipa123",   "role": "viewer",    "department": "HR",  "clearance": "public"},
    "Random":     {"password": "random123",     "role": "guest",     "department": "Ext", "clearance": "none"},
}

# Role hierarchy
ROLE_LEVEL = {"admin": 4, "developer": 3, "viewer": 2, "guest": 1}

# ABAC policy: resource → minimum required attributes
ABAC_POLICIES = {
    "secret_files":    {"min_role": "admin",     "min_clearance": "top-secret",  "departments": ["IT"]},
    "source_code":     {"min_role": "developer", "min_clearance": "confidential","departments": ["IT", "Eng"]},
    "reports":         {"min_role": "viewer",    "min_clearance": "public",      "departments": ["IT", "Eng", "HR"]},
    "public_data":     {"min_role": "guest",     "min_clearance": "none",        "departments": ["IT", "Eng", "HR", "Ext"]},
}

CLEARANCE_LEVEL = {"top-secret": 4, "confidential": 3, "restricted": 2, "public": 1, "none": 0}

# Key store: key_id → {key_bytes, created_at, owner, status, algorithm, rotated_from}
KEY_STORE = {}

# Encrypted blobs: blob_id → {ciphertext, key_id, resource, owner, created_at}
ENCRYPTED_BLOBS = {}

# Audit log
AUDIT_LOG = []

# ─── Helpers ───────────────────────────────────────────────────────────────────

def log_event(user, action, resource, result, detail=""):
    AUDIT_LOG.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user":      user,
        "role":      USERS.get(user, {}).get("role", "unknown"),
        "action":    action,
        "resource":  resource,
        "result":    result,
        "detail":    detail,
    })

def check_abac(username, resource):
    user = USERS.get(username)
    if not user:
        return False, "User not found"
    policy = ABAC_POLICIES.get(resource)
    if not policy:
        return False, "Resource policy not defined"
    if ROLE_LEVEL.get(user["role"], 0) < ROLE_LEVEL.get(policy["min_role"], 99):
        return False, f"Role '{user['role']}' insufficient (need '{policy['min_role']}')"
    if CLEARANCE_LEVEL.get(user["clearance"], 0) < CLEARANCE_LEVEL.get(policy["min_clearance"], 99):
        return False, f"Clearance '{user['clearance']}' insufficient"
    if user["department"] not in policy["departments"]:
        return False, f"Department '{user['department']}' not permitted"
    return True, "Access granted"

def generate_key_internal(owner, algorithm="AES-256"):
    key_id = "key-" + secrets.token_hex(6)
    if algorithm == "AES-256":
        key_bytes = os.urandom(32)
    else:
        key_bytes = Fernet.generate_key()
    KEY_STORE[key_id] = {
        "key_bytes":    key_bytes,
        "algorithm":    algorithm,
        "owner":        owner,
        "created_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status":       "active",
        "rotated_from": None,
    }
    return key_id

def encrypt_data(plaintext: str, key_id: str):
    entry = KEY_STORE.get(key_id)
    if not entry or entry["status"] != "active":
        return None, "Key not found or inactive"
    key_bytes = entry["key_bytes"]
    if entry["algorithm"] == "AES-256":
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(plaintext.encode()) + enc.finalize()
        payload = base64.b64encode(iv + ct).decode()
    else:
        f = Fernet(key_bytes)
        payload = f.encrypt(plaintext.encode()).decode()
    return payload, None

def decrypt_data(payload: str, key_id: str):
    entry = KEY_STORE.get(key_id)
    if not entry:
        return None, "Key not found"
    if entry["status"] == "revoked":
        return None, "Key has been revoked — decryption blocked"
    key_bytes = entry["key_bytes"]
    try:
        if entry["algorithm"] == "AES-256":
            raw = base64.b64decode(payload)
            iv, ct = raw[:16], raw[16:]
            cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
            dec = cipher.decryptor()
            pt = dec.update(ct) + dec.finalize()
            return pt.decode(), None
        else:
            f = Fernet(key_bytes)
            return f.decrypt(payload.encode()).decode(), None
    except Exception as e:
        return None, f"Decryption failed: {str(e)}"

# ─── Seed some initial keys and blobs ──────────────────────────────────────────

_k1 = generate_key_internal("alice", "AES-256")
_k2 = generate_key_internal("bob",   "Fernet")
ct1, _ = encrypt_data("TOP SECRET: Q4 financial projections — internal use only.", _k1)
ct2, _ = encrypt_data("DB_PASSWORD=s3cur3P@ss  API_KEY=sk-demo-abc123xyz", _k2)
ENCRYPTED_BLOBS["blob-001"] = {"ciphertext": ct1, "key_id": _k1, "resource": "secret_files",  "owner": "alice", "label": "Q4 Financials",    "created_at": "2025-01-10 09:00:00"}
ENCRYPTED_BLOBS["blob-002"] = {"ciphertext": ct2, "key_id": _k2, "resource": "source_code",   "owner": "bob",   "label": "Dev Secrets",      "created_at": "2025-01-10 09:05:00"}

# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    u, p = data.get("username"), data.get("password")
    user = USERS.get(u)
    if user and user["password"] == p:
        session["username"] = u
        log_event(u, "LOGIN", "auth", "SUCCESS")
        return jsonify({"ok": True, "username": u, "role": user["role"],
                        "department": user["department"], "clearance": user["clearance"]})
    log_event(u or "unknown", "LOGIN", "auth", "DENIED", "Bad credentials")
    return jsonify({"ok": False, "error": "Invalid credentials"}), 401

@app.route("/api/logout", methods=["POST"])
def logout():
    u = session.pop("username", "unknown")
    log_event(u, "LOGOUT", "auth", "SUCCESS")
    return jsonify({"ok": True})

@app.route("/api/me")
def me():
    u = session.get("username")
    if not u:
        return jsonify({"ok": False}), 401
    user = USERS[u]
    return jsonify({"ok": True, "username": u, **{k: v for k, v in user.items() if k != "password"}})

@app.route("/api/access/<resource>", methods=["GET"])
def check_access(resource):
    u = session.get("username")
    if not u:
        return jsonify({"ok": False, "error": "Not logged in"}), 401
    allowed, reason = check_abac(u, resource)
    result = "GRANTED" if allowed else "DENIED"
    log_event(u, "ACCESS_CHECK", resource, result, reason)
    return jsonify({"ok": True, "allowed": allowed, "reason": reason, "resource": resource})

@app.route("/api/keys", methods=["GET"])
def list_keys():
    u = session.get("username")
    if not u:
        return jsonify({"ok": False}), 401
    role = USERS[u]["role"]
    result = []
    for kid, entry in KEY_STORE.items():
        if role == "admin" or entry["owner"] == u:
            result.append({
                "key_id":       kid,
                "algorithm":    entry["algorithm"],
                "owner":        entry["owner"],
                "created_at":   entry["created_at"],
                "status":       entry["status"],
                "rotated_from": entry["rotated_from"],
                "key_preview":  base64.b64encode(entry["key_bytes"]).decode()[:16] + "...",
            })
    return jsonify({"ok": True, "keys": result})

@app.route("/api/keys/generate", methods=["POST"])
def generate_key():
    u = session.get("username")
    if not u:
        return jsonify({"ok": False}), 401
    if USERS[u]["role"] not in ("admin", "developer"):
        log_event(u, "KEY_GENERATE", "key-store", "DENIED", "Insufficient role")
        return jsonify({"ok": False, "error": "Only admin/developer can generate keys"}), 403
    data = request.json
    algo = data.get("algorithm", "AES-256")
    kid = generate_key_internal(u, algo)
    log_event(u, "KEY_GENERATE", kid, "SUCCESS", f"Algorithm: {algo}")
    return jsonify({"ok": True, "key_id": kid, "algorithm": algo,
                    "key_preview": base64.b64encode(KEY_STORE[kid]["key_bytes"]).decode()[:16] + "..."})

@app.route("/api/keys/<key_id>/rotate", methods=["POST"])
def rotate_key(key_id):
    u = session.get("username")
    if not u:
        return jsonify({"ok": False}), 401
    entry = KEY_STORE.get(key_id)
    if not entry:
        return jsonify({"ok": False, "error": "Key not found"}), 404
    if USERS[u]["role"] != "admin" and entry["owner"] != u:
        log_event(u, "KEY_ROTATE", key_id, "DENIED", "Not owner/admin")
        return jsonify({"ok": False, "error": "Permission denied"}), 403
    old_status = entry["status"]
    entry["status"] = "rotated"
    new_kid = "key-" + secrets.token_hex(6)
    KEY_STORE[new_kid] = {
        "key_bytes":    os.urandom(32) if entry["algorithm"] == "AES-256" else Fernet.generate_key(),
        "algorithm":    entry["algorithm"],
        "owner":        entry["owner"],
        "created_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status":       "active",
        "rotated_from": key_id,
    }
    log_event(u, "KEY_ROTATE", key_id, "SUCCESS", f"New key: {new_kid}")
    return jsonify({"ok": True, "old_key_id": key_id, "new_key_id": new_kid})

@app.route("/api/keys/<key_id>/revoke", methods=["POST"])
def revoke_key(key_id):
    u = session.get("username")
    if not u:
        return jsonify({"ok": False}), 401
    if USERS[u]["role"] != "admin":
        log_event(u, "KEY_REVOKE", key_id, "DENIED", "Not admin")
        return jsonify({"ok": False, "error": "Only admin can revoke keys"}), 403
    entry = KEY_STORE.get(key_id)
    if not entry:
        return jsonify({"ok": False, "error": "Key not found"}), 404
    entry["status"] = "revoked"
    log_event(u, "KEY_REVOKE", key_id, "SUCCESS")
    return jsonify({"ok": True, "key_id": key_id, "status": "revoked"})

@app.route("/api/encrypt", methods=["POST"])
def encrypt_endpoint():
    u = session.get("username")
    if not u:
        return jsonify({"ok": False}), 401
    data = request.json
    plaintext = data.get("plaintext", "").strip()
    key_id    = data.get("key_id", "").strip()
    resource  = data.get("resource", "public_data")
    label     = data.get("label", "").strip()

    # ── Input validation ──────────────────────────────────────────
    if not plaintext:
        return jsonify({"ok": False, "error": "Cannot encrypt empty content"}), 400
    if len(plaintext) < 3:
        return jsonify({"ok": False, "error": "Content too short (minimum 3 characters)"}), 400
    if len(plaintext) > 50000:
        return jsonify({"ok": False, "error": f"Content too large ({len(plaintext)//1000}KB). Max 50KB."}), 400
    if not key_id:
        return jsonify({"ok": False, "error": "No encryption key selected — generate a key first"}), 400
    if not label:
        label = f"File-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    allowed, reason = check_abac(u, resource)
    if not allowed:
        log_event(u, "ENCRYPT", resource, "DENIED", reason)
        return jsonify({"ok": False, "error": reason}), 403
    # Key ownership check — you can only encrypt with YOUR OWN key
    key_entry = KEY_STORE.get(key_id)
    if not key_entry:
        return jsonify({"ok": False, "error": "Key not found"}), 404
    if key_entry["owner"] != u:
        log_event(u, "ENCRYPT", resource, "DENIED", f"Key {key_id} belongs to '{key_entry['owner']}', not '{u}'")
        return jsonify({"ok": False, "error": f"Permission denied — key '{key_id}' belongs to '{key_entry['owner']}'. You can only encrypt with your own keys."}), 403
    ct, err = encrypt_data(plaintext, key_id)
    if err:
        log_event(u, "ENCRYPT", resource, "FAILED", err)
        return jsonify({"ok": False, "error": err}), 400
    blob_id = "blob-" + secrets.token_hex(4)
    filename = data.get("filename") or None
    ENCRYPTED_BLOBS[blob_id] = {
        "ciphertext": ct, "key_id": key_id, "resource": resource,
        "owner": u, "label": label, "filename": filename,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    log_event(u, "ENCRYPT", resource, "SUCCESS", f"Blob: {blob_id}, Key: {key_id}")
    return jsonify({"ok": True, "blob_id": blob_id, "ciphertext_preview": ct[:40] + "..."})

@app.route("/api/decrypt", methods=["POST"])
def decrypt_endpoint():
    u = session.get("username")
    if not u:
        return jsonify({"ok": False}), 401
    data    = request.json
    blob_id = data.get("blob_id", "")
    blob    = ENCRYPTED_BLOBS.get(blob_id)
    if not blob:
        return jsonify({"ok": False, "error": "Blob not found"}), 404
    allowed, reason = check_abac(u, blob["resource"])
    if not allowed:
        log_event(u, "DECRYPT", blob_id, "DENIED", reason)
        return jsonify({"ok": False, "error": reason}), 403
    pt, err = decrypt_data(blob["ciphertext"], blob["key_id"])
    if err:
        log_event(u, "DECRYPT", blob_id, "FAILED", err)
        return jsonify({"ok": False, "error": err}), 400
    log_event(u, "DECRYPT", blob_id, "SUCCESS", f"Resource: {blob['resource']}")
    role = USERS[u]["role"]
    can_see_internals = role in ("admin", "developer")
    return jsonify({
        "ok":        True,
        "plaintext": pt,
        "resource":  blob["resource"],
        "owner":     blob["owner"] if can_see_internals else None,
        "filename":  blob.get("filename"),
    })

@app.route("/api/blobs", methods=["GET"])
def list_blobs():
    u = session.get("username")
    if not u:
        return jsonify({"ok": False}), 401
    role = USERS[u]["role"]
    can_see_internals = role in ("admin", "developer")
    result = []
    for bid, b in ENCRYPTED_BLOBS.items():
        allowed, _ = check_abac(u, b["resource"])
        if allowed:
            key_entry  = KEY_STORE.get(b["key_id"], {})
            key_status = key_entry.get("status", "unknown")
            # rotated keys can still decrypt old blobs — only revoked blocks decryption
            can_decrypt = key_status in ("active", "rotated")
            entry = {
                "blob_id":     bid,
                "label":       b["label"],
                "resource":    b["resource"],
                "created_at":  b["created_at"],
                "key_status":  key_status,
                "can_decrypt": can_decrypt,
                "owner":       b["owner"]  if can_see_internals else None,
                "key_id":      b["key_id"] if can_see_internals else None,
                "preview":     b["ciphertext"][:32] + "..." if can_see_internals else None,
            }
            result.append(entry)
    return jsonify({"ok": True, "blobs": result})

@app.route("/api/audit", methods=["GET"])
def audit():
    u = session.get("username")
    if not u:
        return jsonify({"ok": False}), 401
    if USERS[u]["role"] != "admin":
        log_event(u, "AUDIT_VIEW", "audit-log", "DENIED", "Not admin")
        return jsonify({"ok": False, "error": "Only admin can view audit log"}), 403
    return jsonify({"ok": True, "log": list(reversed(AUDIT_LOG))})

@app.route("/api/policy", methods=["GET"])
def policy():
    u = session.get("username")
    if not u:
        return jsonify({"ok": False}), 401
    return jsonify({"ok": True, "policies": ABAC_POLICIES, "roles": ROLE_LEVEL, "clearance_levels": CLEARANCE_LEVEL})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
