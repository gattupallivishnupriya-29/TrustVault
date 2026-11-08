
from datetime import datetime, timezone

from flask_login import UserMixin
from extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), nullable=False, default="viewer")
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


class Category(db.Model):
    __tablename__ = "categories"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255))


class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    storage_key = db.Column(db.String(100), unique=True, nullable=False)

    owner_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False
    )

    category_id = db.Column(
        db.Integer, db.ForeignKey("categories.id"), nullable=True
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    is_deleted = db.Column(
        db.Boolean, default=False, nullable=False
    )

    deleted_at = db.Column(
        db.DateTime(timezone=True), nullable=True
    )


class DocumentPermission(db.Model):
    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)

    document_id = db.Column(
        db.Integer, db.ForeignKey("documents.id"), nullable=False
    )

    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False
    )

    can_read = db.Column(db.Boolean, default=False, nullable=False)
    can_edit = db.Column(db.Boolean, default=False, nullable=False)

    __table_args__ = (
        db.UniqueConstraint(
            "document_id", "user_id",
            name="unique_document_user_permission"
        ),
    )


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)

    actor_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True
    )

    document_id = db.Column(
        db.Integer, db.ForeignKey("documents.id"), nullable=True
    )

    action = db.Column(db.String(50), nullable=False)
    outcome = db.Column(db.String(20), nullable=False)
    details = db.Column(db.Text)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    previous_hash = db.Column(db.String(64))
    entry_hash = db.Column(db.String(64))
