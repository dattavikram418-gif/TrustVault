import os, tempfile
import pytest
from fastapi.testclient import TestClient

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("STORAGE_PATH", str(tmp_path / "storage"))
    # Reload config-dependent app modules for isolated test database/storage.
    import app.config as config
    config.DATABASE_PATH = str(tmp_path / "test.db")
    config.STORAGE_PATH = tmp_path / "storage"
    import app.db as database
    database.DATABASE_PATH = str(tmp_path / "test.db")
    import app.main as main
    main.STORAGE_PATH = tmp_path / "storage"
    main.STORAGE_PATH.mkdir(parents=True, exist_ok=True)
    main.startup()
    with TestClient(main.app) as c:
        yield c
