import os, uuid, hashlib, mimetypes, json
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field
import jwt
from . import db
from .config import STORAGE_PATH, MAX_UPLOAD_MB, ALLOWED_EXTENSIONS
from .security import hash_password, verify_password, create_token, decode_token, audit_hash, verify_audit_chain

app = FastAPI(title="TrustVault API", version="1.0.0",
              description="Private document vault with per-document authorization and tamper-evident audit events.")
bearer = HTTPBearer(auto_error=False)
STORAGE_PATH.mkdir(parents=True, exist_ok=True)

@app.on_event("startup")
def startup():
    db.init_db()
    # Demo accounts are created only when the database is empty.
    with db.connect() as con:
        if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            for username, password, role in [
                ("admin", "Admin@12345", "admin"),
                ("owner", "Owner@12345", "owner"),
                ("viewer", "Viewer@12345", "viewer")
            ]:
                con.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                            (username, hash_password(password), role))

def audit(actor, action, document_id=None, target_user_id=None, outcome="success",
          request=None, details=None):
    details_json = json.dumps(details or {}, sort_keys=True)
    ip = request.client.host if request and request.client else None
    actor_id = actor["id"] if actor else None
    actor_name = actor["username"] if actor else "anonymous"
    with db.connect() as con:
        previous = con.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = previous["entry_hash"] if previous else "GENESIS"
        cur = con.execute("""INSERT INTO audit_logs
          (actor_id,actor_name,action,document_id,target_user_id,outcome,ip_address,details,previous_hash,entry_hash)
          VALUES(?,?,?,?,?,?,?,?,?,?)""",
          (actor_id, actor_name, action, document_id, target_user_id, outcome, ip,
           details_json, prev_hash, "PENDING"))
        entry_id = cur.lastrowid
        occurred = con.execute("SELECT occurred_at FROM audit_logs WHERE id=?", (entry_id,)).fetchone()["occurred_at"]
        payload = {"id":entry_id,"occurred_at":occurred,"actor_id":actor_id,"actor_name":actor_name,
          "action":action,"document_id":document_id,"target_user_id":target_user_id,"outcome":outcome,
          "ip_address":ip,"details":details_json,"previous_hash":prev_hash}
        con.execute("UPDATE audit_logs SET entry_hash=? WHERE id=?", (audit_hash(payload), entry_id))

def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    if not credentials:
        raise HTTPException(401, "Authentication required")
    try:
        claims = decode_token(credentials.credentials)
        with db.connect() as con:
            user = con.execute("SELECT id,username,role,active FROM users WHERE id=?", (int(claims["sub"]),)).fetchone()
        if not user or not user["active"]:
            raise HTTPException(401, "Account unavailable")
        return dict(user)
    except (jwt.InvalidTokenError, ValueError, KeyError):
        raise HTTPException(401, "Invalid or expired token")

def require_role(*roles):
    def dependency(user=Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(403, "Insufficient role")
        return user
    return dependency

def get_doc(document_id):
    with db.connect() as con:
        row = con.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
    return dict(row) if row else None

def permission_for(user, doc):
    if user["id"] == doc["owner_id"]:
        return "owner"
    with db.connect() as con:
        row = con.execute("SELECT permission FROM permissions WHERE document_id=? AND user_id=?",
                          (doc["id"], user["id"])).fetchone()
    return row["permission"] if row else None

def authorize(user, doc, needed, request, action):
    permission = permission_for(user, doc)
    allowed = permission == "owner" or permission == "edit" or (needed == "read" and permission == "read")
    if not allowed:
        audit(user, action, doc["id"], outcome="denied", request=request,
              details={"required":needed})
        raise HTTPException(404, "Document not found")
    return permission

class LoginBody(BaseModel):
    username: str
    password: str

class GrantBody(BaseModel):
    username: str
    permission: str = Field(pattern="^(read|edit)$")

class MetadataBody(BaseModel):
    filename: Optional[str] = Field(default=None, min_length=1, max_length=255)
    category: Optional[str] = Field(default=None, min_length=1, max_length=80)


@app.get("/", response_class=HTMLResponse)
def home():
    return (
        Path(__file__).parent / "static" / "index.html"
    ).read_text(encoding="utf-8")

@app.post("/api/auth/login")
def login(body: LoginBody, request: Request):
    with db.connect() as con:
        user = con.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
    if not user or not user["active"] or not verify_password(body.password, user["password_hash"]):
        audit(None, "login", outcome="denied", request=request, details={"username":body.username})
        raise HTTPException(401, "Invalid username or password")
    u = dict(user)
    audit(u, "login", request=request)
    return {"access_token":create_token(u), "token_type":"bearer",
            "user":{"id":u["id"],"username":u["username"],"role":u["role"]}}

@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    return user

@app.post("/api/users")
def create_user(username: str = Form(...), password: str = Form(...),
                role: str = Form(...), admin=Depends(require_role("admin"))):
    if role not in {"admin","owner","viewer"} or len(password) < 12:
        raise HTTPException(400, "Role invalid or password must be at least 12 characters")
    try:
        with db.connect() as con:
            cur = con.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                              (username, hash_password(password), role))
        audit(admin, "user_created", details={"username":username,"role":role})
        return {"id":cur.lastrowid,"username":username,"role":role}
    except Exception:
        raise HTTPException(409, "Username already exists")

@app.post("/api/documents")
async def upload_document(request: Request, file: UploadFile = File(...),
                          category: str = Form("General"),
                          user=Depends(require_role("owner"))):
    original = Path(file.filename or "upload").name
    ext = Path(original).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        audit(user, "upload", outcome="denied", request=request, details={"reason":"extension"})
        raise HTTPException(415, "File type not allowed")
    data = await file.read(MAX_UPLOAD_MB * 1024 * 1024 + 1)
    if not data or len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, "Empty file or upload exceeds size limit")
    signatures = {".pdf":data.startswith(b"%PDF"), ".png":data.startswith(b"\x89PNG"),
                  ".jpg":data.startswith(b"\xff\xd8\xff"), ".jpeg":data.startswith(b"\xff\xd8\xff"),
                  ".txt":True, ".docx":data.startswith(b"PK")}
    if not signatures.get(ext, False):
        audit(user, "upload", outcome="denied", request=request, details={"reason":"file_signature"})
        raise HTTPException(415, "File content does not match extension")
    doc_id = str(uuid.uuid4())
    stored = f"{uuid.uuid4().hex}{ext}"
    digest = hashlib.sha256(data).hexdigest()
    target = STORAGE_PATH / stored
    target.write_bytes(data)
    try:
        with db.connect() as con:
            con.execute("""INSERT INTO documents(id,owner_id,filename,category,stored_name,size_bytes,sha256)
                VALUES(?,?,?,?,?,?,?)""",
                (doc_id,user["id"],original,category,stored,len(data),digest))
        audit(user, "upload", doc_id, request=request, details={"filename":original,"sha256":digest,"size":len(data)})
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return {"id":doc_id,"filename":original,"category":category,"size_bytes":len(data),"sha256":digest}

@app.get("/api/documents")
def list_documents(request: Request, q: str = "", owner: str = "", category: str = "",
                   date_from: str = "", date_to: str = "", user=Depends(current_user)):
    # Never expose documents merely because a user can see their owner's folder.
    with db.connect() as con:
        rows = con.execute("""SELECT DISTINCT d.*,u.username AS owner_name FROM documents d
          JOIN users u ON u.id=d.owner_id
          LEFT JOIN permissions p ON p.document_id=d.id AND p.user_id=?
          WHERE (d.owner_id=? OR p.user_id=?) AND
          (?='' OR lower(d.filename) LIKE lower(?)) AND
          (?='' OR lower(u.username)=lower(?)) AND
          (?='' OR lower(d.category)=lower(?)) AND
          (?='' OR date(d.created_at)>=date(?)) AND
          (?='' OR date(d.created_at)<=date(?))
          ORDER BY d.created_at DESC""",
          (user["id"],user["id"],user["id"],q,f"%{q}%",owner,owner,category,category,
           date_from,date_from,date_to,date_to)).fetchall()
    result=[]
    for r in rows:
        d=dict(r); d.pop("stored_name",None); d["permission"]=permission_for(user,d)
        result.append(d)
    audit(user,"document_list",request=request,details={"count":len(result)})
    return result

@app.get("/api/documents/{document_id}")
def document_detail(document_id: str, request: Request, user=Depends(current_user)):
    doc=get_doc(document_id)
    if not doc:
        audit(user,"metadata_read",document_id,outcome="denied",request=request)
        raise HTTPException(404,"Document not found")
    authorize(user,doc,"read",request,"metadata_read")
    doc.pop("stored_name",None)
    doc["permission"]=permission_for(user,get_doc(document_id))
    return doc

@app.get("/api/documents/{document_id}/download")
def download_document(document_id: str, request: Request, user=Depends(current_user)):
    doc=get_doc(document_id)
    if not doc:
        audit(user,"download",document_id,outcome="denied",request=request)
        raise HTTPException(404,"Document not found")
    authorize(user,doc,"read",request,"download")
    path=STORAGE_PATH / doc["stored_name"]
    if not path.is_file():
        audit(user,"download",document_id,outcome="error",request=request,details={"reason":"missing_storage"})
        raise HTTPException(410,"Stored file unavailable")
    audit(user,"download",document_id,request=request,details={"sha256":doc["sha256"]})
    return FileResponse(path, filename=doc["filename"], media_type="application/octet-stream")

@app.patch("/api/documents/{document_id}")
def update_document(document_id: str, body: MetadataBody, request: Request, user=Depends(current_user)):
    doc=get_doc(document_id)
    if not doc:
        raise HTTPException(404,"Document not found")
    authorize(user,doc,"edit",request,"document_update")
    fields={k:v for k,v in body.model_dump(exclude_none=True).items()}
    if not fields:
        raise HTTPException(400,"No changes supplied")
    fields["updated_at"]="CURRENT_TIMESTAMP"
    with db.connect() as con:
        sets=", ".join(f"{k}=?" for k in fields if k!="updated_at")
        vals=[v for k,v in fields.items() if k!="updated_at"]
        con.execute(f"UPDATE documents SET {sets}, updated_at=CURRENT_TIMESTAMP WHERE id=?", (*vals,document_id))
    audit(user,"document_update",document_id,request=request,details={"fields":list(fields)})
    return {"status":"updated"}

@app.put("/api/documents/{document_id}/permissions/{target_username}")
def grant_permission(document_id: str, target_username: str, body: GrantBody,
                     request: Request, user=Depends(current_user)):
    doc=get_doc(document_id)
    if not doc:
        raise HTTPException(404,"Document not found")
    if user["id"] != doc["owner_id"]:
        audit(user,"permission_grant",document_id,outcome="denied",request=request,
              details={"target":target_username})
        raise HTTPException(404,"Document not found")
    with db.connect() as con:
        target=con.execute("SELECT id FROM users WHERE username=? AND active=1",(target_username,)).fetchone()
        if not target:
            raise HTTPException(404,"User not found")
        if target["id"] == doc["owner_id"]:
            raise HTTPException(400,"Owner already has full access")
        con.execute("""INSERT INTO permissions(document_id,user_id,permission,granted_by)
          VALUES(?,?,?,?) ON CONFLICT(document_id,user_id) DO UPDATE SET permission=excluded.permission,
          granted_by=excluded.granted_by,created_at=CURRENT_TIMESTAMP""",
          (document_id,target["id"],body.permission,user["id"]))
    audit(user,"permission_grant",document_id,target["id"],request=request,
          details={"permission":body.permission})
    return {"status":"granted","username":target_username,"permission":body.permission}

@app.delete("/api/documents/{document_id}/permissions/{target_username}")
def revoke_permission(document_id: str, target_username: str, request: Request,
                      user=Depends(current_user)):
    doc=get_doc(document_id)
    if not doc or user["id"] != doc["owner_id"]:
        if doc: audit(user,"permission_revoke",document_id,outcome="denied",request=request)
        raise HTTPException(404,"Document not found")
    with db.connect() as con:
        target=con.execute("SELECT id FROM users WHERE username=?",(target_username,)).fetchone()
        if not target: raise HTTPException(404,"User not found")
        con.execute("DELETE FROM permissions WHERE document_id=? AND user_id=?",(document_id,target["id"]))
    audit(user,"permission_revoke",document_id,target["id"],request=request)
    return {"status":"revoked","username":target_username}

@app.delete("/api/documents/{document_id}")
def delete_document(document_id: str, request: Request, user=Depends(current_user)):
    doc=get_doc(document_id)
    if not doc or (user["id"] != doc["owner_id"] and user["role"] != "admin"):
        if doc: audit(user,"document_delete",document_id,outcome="denied",request=request)
        raise HTTPException(404,"Document not found")
    audit(user,"document_delete",document_id,request=request,details={"filename":doc["filename"]})
    (STORAGE_PATH / doc["stored_name"]).unlink(missing_ok=True)
    with db.connect() as con:
        con.execute("DELETE FROM documents WHERE id=?",(document_id,))
    return {"status":"deleted"}

@app.get("/api/admin/audit")
def admin_audit(limit: int = 200, user=Depends(require_role("admin"))):
    limit=max(1,min(limit,1000))
    with db.connect() as con:
        rows=con.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return [dict(r) for r in rows]

@app.get("/api/admin/audit/verify")
def verify_audit(user=Depends(require_role("admin"))):
    with db.connect() as con:
        rows=con.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall()
    return {"valid":verify_audit_chain(rows),"entries_checked":len(rows)}

@app.get("/api/admin/users")
def users(user=Depends(require_role("admin"))):
    with db.connect() as con:
        rows=con.execute("SELECT id,username,role,active,created_at FROM users ORDER BY id").fetchall()
    return [dict(r) for r in rows]
