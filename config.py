
import os
from dotenv import load_dotenv
from sqlalchemy.engine import URL

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")

    SQLALCHEMY_DATABASE_URI = URL.create(
        drivername="mysql+pymysql",
        username=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", 3306)),
        database=os.getenv("DB_NAME")
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Private document storage folder
    UPLOAD_FOLDER = os.path.join(
        BASE_DIR, "instance", "private_uploads"
    )

    # Maximum upload size: 10 MB
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024

    # Allowed document formats
    ALLOWED_EXTENSIONS = {
        "pdf", "doc", "docx", "txt", "png", "jpg", "jpeg"
    }
