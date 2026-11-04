import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "development-jwt-secret-change-before-deploy-2026")
AUDIT_SECRET = os.getenv("AUDIT_SECRET", "development-audit-secret-change-before-deploy-2026")
DATABASE_PATH = os.getenv("DATABASE_PATH", "./data/trustvault.db")
STORAGE_PATH = Path(os.getenv("STORAGE_PATH", "./private_storage"))
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "30"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "10"))
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg", ".docx"}
