import hashlib, hmac, json, secrets
from datetime import datetime, timedelta, timezone
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from .config import JWT_SECRET, ACCESS_TOKEN_MINUTES, AUDIT_SECRET

_hasher = PasswordHasher()

def hash_password(password: str) -> str:
    return _hasher.hash(password)

def verify_password(password: str, encoded: str) -> bool:
    try:
        return _hasher.verify(encoded, password)
    except VerifyMismatchError:
        return False

def create_token(user: dict) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user["id"]), "role": user["role"],
               "iat": now, "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
               "jti": secrets.token_urlsafe(16)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

def audit_hash(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(AUDIT_SECRET.encode(), raw, hashlib.sha256).hexdigest()

def verify_audit_chain(rows) -> bool:
    previous = "GENESIS"
    for row in rows:
        data = {
            "id": row["id"], "occurred_at": row["occurred_at"],
            "actor_id": row["actor_id"], "actor_name": row["actor_name"],
            "action": row["action"], "document_id": row["document_id"],
            "target_user_id": row["target_user_id"], "outcome": row["outcome"],
            "ip_address": row["ip_address"], "details": row["details"],
            "previous_hash": row["previous_hash"]
        }
        if row["previous_hash"] != previous or not hmac.compare_digest(audit_hash(data), row["entry_hash"]):
            return False
        previous = row["entry_hash"]
    return True
