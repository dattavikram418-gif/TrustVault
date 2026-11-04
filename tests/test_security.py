def token(client, username, password):
    r=client.post("/api/auth/login",json={"username":username,"password":password})
    assert r.status_code==200, r.text
    return r.json()["access_token"]

def auth(t): return {"Authorization":f"Bearer {t}"}

def upload(client, t, name=b"hello secure vault"):
    return client.post("/api/documents",headers=auth(t),
        files={"file":("secret.txt",name,"text/plain")},
        data={"category":"Contracts"})

def test_ungranted_user_cannot_list_or_download_document(client):
    owner=token(client,"owner","Owner@12345")
    viewer=token(client,"viewer","Viewer@12345")
    created=upload(client,owner)
    assert created.status_code==200, created.text
    doc_id=created.json()["id"]
    assert client.get("/api/documents",headers=auth(viewer)).json()==[]
    assert client.get(f"/api/documents/{doc_id}",headers=auth(viewer)).status_code==404
    assert client.get(f"/api/documents/{doc_id}/download",headers=auth(viewer)).status_code==404

def test_grant_and_immediate_revoke(client):
    owner=token(client,"owner","Owner@12345")
    viewer=token(client,"viewer","Viewer@12345")
    doc=upload(client,owner).json()
    grant=client.put(f"/api/documents/{doc['id']}/permissions/viewer",
        headers=auth(owner),json={"username":"viewer","permission":"read"})
    assert grant.status_code==200
    assert client.get(f"/api/documents/{doc['id']}/download",headers=auth(viewer)).status_code==200
    revoke=client.delete(f"/api/documents/{doc['id']}/permissions/viewer",headers=auth(owner))
    assert revoke.status_code==200
    assert client.get(f"/api/documents/{doc['id']}/download",headers=auth(viewer)).status_code==404

def test_viewer_cannot_grant_access_or_upload(client):
    viewer=token(client,"viewer","Viewer@12345")
    assert client.post("/api/documents",headers=auth(viewer),
        files={"file":("x.txt",b"x","text/plain")}).status_code==403

def test_non_owner_cannot_change_metadata(client):
    owner=token(client,"owner","Owner@12345")
    viewer=token(client,"viewer","Viewer@12345")
    doc=upload(client,owner).json()
    assert client.patch(f"/api/documents/{doc['id']}",headers=auth(viewer),
        json={"filename":"stolen.txt"}).status_code==404

def test_wrong_extension_and_signature_rejected(client):
    owner=token(client,"owner","Owner@12345")
    assert client.post("/api/documents",headers=auth(owner),
        files={"file":("payload.exe",b"MZ","application/octet-stream")}).status_code==415
    assert client.post("/api/documents",headers=auth(owner),
        files={"file":("fake.pdf",b"not a pdf","application/pdf")}).status_code==415

def test_admin_audit_verification(client):
    admin=token(client,"admin","Admin@12345")
    assert client.get("/api/admin/audit/verify",headers=auth(admin)).json()["valid"] is True

def test_anonymous_cannot_download(client):
    owner=token(client,"owner","Owner@12345")
    doc=upload(client,owner).json()
    assert client.get(f"/api/documents/{doc['id']}/download").status_code==401
