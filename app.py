import os
import secrets
import hashlib
import hmac
import json

from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from werkzeug.security import generate_password_hash
from flask_login import (
    LoginManager, login_user,
    logout_user, login_required, current_user
)

from werkzeug.security import (
    generate_password_hash, check_password_hash
)

from sqlalchemy import text, or_

from config import Config
from extensions import db, login_manager, csrf
from models import User, Category, Document, DocumentPermission, AuditLog


def create_app():
    app = Flask(__name__)
    def record_audit(
        actor_id,
        document_id,
        action,
        outcome,
        details=""
        ):

        # Get the previous audit record
        previous_record = AuditLog.query.order_by(
            AuditLog.id.desc()
        ).first()

        previous_hash = (
            previous_record.entry_hash
            if previous_record else "GENESIS"
        )

        # Current timestamp
        timestamp = datetime.now(timezone.utc).replace(microsecond=0)

        # Prepare audit information
        audit_data = {
            "actor_id": actor_id,
            "document_id": document_id,
            "action": action,
            "outcome": outcome,
            "details": details,
            "created_at": timestamp.isoformat(),
            "previous_hash": previous_hash
        }

        # Generate a secure hash
        audit_text = json.dumps(
            audit_data,
            sort_keys=True
        )

        secret = app.config["SECRET_KEY"].encode("utf-8")

        entry_hash = hmac.new(
            secret,
            audit_text.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        # Save audit information
        log = AuditLog(
            actor_id=actor_id,
            document_id=document_id,
            action=action,
            outcome=outcome,
            details=details,
            created_at=timestamp,
            previous_hash=previous_hash,
            entry_hash=entry_hash
        )

        db.session.add(log)
    def verify_audit_chain():

        # Records 1–10 belong to the historical chain
        LEGACY_LAST_ID = 10

        # Get the last historical record
        baseline = AuditLog.query.filter_by(
            id=LEGACY_LAST_ID
        ).first()

        if baseline is None:
            return False, LEGACY_LAST_ID

        # Verify only records created after the checkpoint
        logs = AuditLog.query.filter(
            AuditLog.id > LEGACY_LAST_ID
        ).order_by(
            AuditLog.id.asc()
        ).all()

        expected_previous_hash = baseline.entry_hash

        secret = app.config["SECRET_KEY"].encode("utf-8")

        for log in logs:

            if log.previous_hash != expected_previous_hash:
                return False, log.id

            timestamp = log.created_at

            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)

            timestamp = timestamp.replace(microsecond=0)

            audit_data = {
                "actor_id": log.actor_id,
                "document_id": log.document_id,
                "action": log.action,
                "outcome": log.outcome,
                "details": log.details,
                "created_at": timestamp.isoformat(),
                "previous_hash": log.previous_hash
            }

            audit_text = json.dumps(
                audit_data,
                sort_keys=True
            )

            expected_hash = hmac.new(
                secret,
                audit_text.encode("utf-8"),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(
                log.entry_hash or "",
                expected_hash
            ):
                return False, log.id

            expected_previous_hash = log.entry_hash

        return True, None
    
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Login settings
    login_manager.login_view = "login"
    login_manager.login_message = "Please log in first."

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Home page
    @app.route("/")
    def home():
        return """
        <h1>Welcome to TrustVault</h1>
        <h2>Secure Document Management System</h2>
        <p>Your documents, your security, your control.</p>
        <a href="/register">Register</a>
        <br><br>
        <a href="/login">Login</a>
        """

    # Registration
    @app.route("/register", methods=["GET", "POST"])
    def register():

        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":

            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            role = request.form.get("role", "viewer")

            if not username or not email or not password:
                flash("Please fill in all fields.", "error")

            elif len(username) > 80 or len(email) > 120:
                flash("Username or email is too long.", "error")

            elif len(password) < 8:
                flash("Password must contain at least 8 characters.", "error")

            elif role not in ("owner", "viewer"):
                flash("Invalid account role.", "error")

            else:
                existing_user = User.query.filter(
                    (User.username == username) |
                    (User.email == email)
                ).first()

                if existing_user:
                    flash("Username or email already exists.", "error")

                else:
                    hashed_password = generate_password_hash(password)

                    new_user = User(
                        username=username,
                        email=email,
                        password_hash=hashed_password,
                        role=role
                    )

                    try:
                        db.session.add(new_user)
                        db.session.commit()

                        flash("Registration successful! Please log in.", "success")
                        return redirect(url_for("login"))

                    except Exception:
                        db.session.rollback()
                        app.logger.exception("Registration failed")
                        flash("Registration failed. Please try again.", "error")

        return render_template("register.html")

    # Login
    @app.route("/login", methods=["GET", "POST"])
    def login():

        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":

            identity = request.form.get("identity", "").strip()
            password = request.form.get("password", "")

            user = User.query.filter(
                (User.username == identity) |
                (User.email == identity.lower())
            ).first()

            if user and user.is_active and check_password_hash(
                user.password_hash, password
            ):
                login_user(user)
                flash("Login successful!", "success")
                return redirect(url_for("dashboard"))

            flash("Invalid username/email or password.", "error")

        return render_template("login.html")
    
    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    def upload_document():

        # Only owners and admins can upload documents
        if current_user.role not in ("owner", "admin"):
            flash("You do not have permission to upload documents.", "error")
            return redirect(url_for("dashboard"))

        if request.method == "POST":

            title = request.form.get("title", "").strip()
            category_name = request.form.get("category", "").strip()
            uploaded_file = request.files.get("document")

            # Check required fields
            if not title or not category_name or not uploaded_file:
                flash("Please fill in all fields.", "error")
                return redirect(url_for("upload_document"))

            if len(title) > 200 or len(category_name) > 100:
                flash("Title or category is too long.", "error")
                return redirect(url_for("upload_document"))

            if not uploaded_file.filename:
                flash("Please select a document.", "error")
                return redirect(url_for("upload_document"))

            # Validate file extension
            original_filename = secure_filename(uploaded_file.filename)

            if not original_filename:
                flash("Invalid filename.", "error")
                return redirect(url_for("upload_document"))

            extension = original_filename.rsplit(".", 1)[-1].lower()

            if "." not in original_filename or extension not in app.config["ALLOWED_EXTENSIONS"]:
                flash("This file format is not allowed.", "error")
                return redirect(url_for("upload_document"))

            # Generate a random storage filename
            storage_key = secrets.token_hex(32) + "." + extension

            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

            file_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                storage_key
            )

            saved_file = False

            try:
                # Save the actual file privately
                uploaded_file.save(file_path)
                saved_file = True

                # Find or create the category
                category = Category.query.filter_by(
                    name=category_name
                ).first()

                if category is None:
                    category = Category(name=category_name)
                    db.session.add(category)
                    db.session.flush()

                # Save document information in MySQL
                new_document = Document(
                    title=title,
                    original_filename=original_filename,
                    storage_key=storage_key,
                    owner_id=current_user.id,
                    category_id=category.id
                )

                db.session.add(new_document)

                # Generate the document ID before creating the audit record
                db.session.flush()

                # Record the successful upload
                record_audit(
                actor_id=current_user.id,
                document_id=new_document.id,
                action="UPLOAD",
                outcome="SUCCESS",
                details=f"Uploaded document: {new_document.original_filename}"
                )

                # Save document and audit record together
                db.session.commit()

                flash("Document uploaded successfully!", "success")
                return redirect(url_for("dashboard"))

            except Exception:
                db.session.rollback()

                # Remove the file if the database operation fails
                if saved_file and os.path.exists(file_path):
                    os.remove(file_path)

                app.logger.exception("Document upload failed")
                flash("Upload failed. Please try again.", "error")
                return redirect(url_for("upload_document"))

        return render_template("upload.html")

    @app.route("/delete/<int:document_id>", methods=["POST"])
    @login_required
    def delete_document(document_id):

        document = Document.query.filter_by(
            id=document_id,
            is_deleted=False
        ).first_or_404()

        # Only owner or admin can delete
        if (
            current_user.role != "admin"
            and document.owner_id != current_user.id
        ):
            record_audit(
                current_user.id,
                document.id,
                "DELETE",
                "DENIED",
                "Unauthorized deletion attempt"
            )
            db.session.commit()
            abort(403)

        # Mark document as deleted
        document.is_deleted = True
        document.deleted_at = datetime.now(timezone.utc)

        record_audit(
            current_user.id,
            document.id,
            "DELETE",
            "SUCCESS",
            f"Document '{document.title}' was soft deleted"
        )

        db.session.commit()

        flash("Document deleted successfully.", "success")

        return redirect(url_for("documents"))

    # Dashboard
    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", user=current_user)

    # Logout
    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        logout_user()
        flash("You have logged out successfully.", "success")
        return redirect(url_for("login"))
    
    @app.route("/documents")
    @login_required
    def documents():

        search = request.args.get("search", "").strip()
        selected_category = request.args.get("category", "").strip()

        # Find documents owned by the current user
        # or shared with the current user.
        shared_document_ids = (
            db.session.query(DocumentPermission.document_id)
            .filter(
                DocumentPermission.user_id == current_user.id,
                DocumentPermission.can_read.is_(True)
            )
            .subquery()
        )

        access_filter = or_(
            Document.owner_id == current_user.id,
            Document.id.in_(shared_document_ids)
        )

        categories = (
            db.session.query(Category)
            .join(Document, Document.category_id == Category.id)
            .filter(
                    access_filter,
                    Document.is_deleted.is_(False)
                )
            .distinct()
            .order_by(Category.name)
            .all()
            )

        query = (
            db.session.query(Document, Category.name)
            .join(Category, Document.category_id == Category.id)
            .filter(
            access_filter,
            Document.is_deleted.is_(False)
            )
        )

        if search:
            search_text = f"%{search}%"
            query = query.filter(
                or_(
                    Document.title.ilike(search_text),
                    Document.original_filename.ilike(search_text)
                )
            )

        if selected_category:
            query = query.filter(Category.name == selected_category)

        documents = query.order_by(Document.created_at.desc()).all()

        return render_template(
            "documents.html",
            user=current_user,
            documents=documents,
            categories=categories,
            search=search,
            selected_category=selected_category
        )
    
    @app.route("/download/<int:document_id>")
    @login_required
    def download_document(document_id):

        # Find the document
        document = Document.query.filter_by(
            id=document_id
        ).first()

        if document is None:
            abort(404)
                # Prevent downloading deleted documents
        if document.is_deleted:
            record_audit(
                actor_id=current_user.id,
                document_id=document.id,
                action="DOWNLOAD",
                outcome="DENIED",
                details="Attempted to download a deleted document"
            )
            db.session.commit()
            abort(404)
        # Check whether the current user owns the document
        is_owner = document.owner_id == current_user.id

        # Check whether the current user has read permission
        permission = DocumentPermission.query.filter_by(
            document_id=document.id,
            user_id=current_user.id,
            can_read=True
        ).first()

        if not is_owner and permission is None:
            record_audit(
                actor_id=current_user.id,
                document_id=document.id,
                action="DOWNLOAD",
                outcome="DENIED",
                details="User attempted to download without read permission"
            )
            db.session.commit()
            abort(403)

        # Validate the stored file name
        if (
            not document.storage_key
            or os.path.basename(document.storage_key) != document.storage_key
        ):
            abort(404)

        # Validate the file path
        upload_folder = os.path.realpath(
            app.config["UPLOAD_FOLDER"]
        )

        file_path = os.path.realpath(
            os.path.join(upload_folder, document.storage_key)
        )

        if os.path.commonpath(
            [upload_folder, file_path]
        ) != upload_folder:
            abort(404)

        if not os.path.isfile(file_path):
            abort(404)

        # Download the file
        response = send_file(
            file_path,
            as_attachment=True,
            download_name=document.original_filename
        )

        response.headers["Cache-Control"] = "no-store"

        # Record successful download
        record_audit(
            actor_id=current_user.id,
            document_id=document.id,
            action="DOWNLOAD",
            outcome="SUCCESS",
            details=f"Downloaded document: {document.original_filename}"
        )

        db.session.commit()

        return response
    
    @app.route("/share/<int:document_id>", methods=["GET", "POST"])
    @login_required
    def share_document(document_id):

        # Only the document owner can manage sharing
        document = Document.query.filter_by(
            id=document_id,
            owner_id=current_user.id,
            is_deleted=False
        ).first_or_404()

        if request.method == "POST":

            recipient_id = request.form.get("recipient_id", type=int)
            access_level = request.form.get("access_level")

            if not recipient_id or access_level not in ("read", "edit"):
                flash("Please select a valid user and permission.", "error")
                return redirect(url_for("share_document", document_id=document.id))

            recipient = User.query.filter_by(
                id=recipient_id,
                is_active=True
            ).first()

            if recipient is None or recipient.id == current_user.id:
                flash("Invalid recipient selected.", "error")
                return redirect(url_for("share_document", document_id=document.id))

            # Find an existing permission
            permission = DocumentPermission.query.filter_by(
                document_id=document.id,
                user_id=recipient.id
            ).first()

            if permission is None:
                permission = DocumentPermission(
                    document_id=document.id,
                    user_id=recipient.id
                )
                db.session.add(permission)

            # Edit permission also includes read permission
            permission.can_read = True
            permission.can_edit = (access_level == "edit")
            try:
                # Record permission grant in audit log
                record_audit(
                    actor_id=current_user.id,
                    document_id=document.id,
                    action="GRANT",
                    outcome="SUCCESS",
                    details=(
                        f"Granted {access_level} access to user ID {recipient.id}"
                    )
                )

                # Save permission and audit record together
                db.session.commit()

                flash("Document access granted successfully!", "success")

            except Exception:
                db.session.rollback()
                app.logger.exception("Permission update failed")
                flash("Unable to grant access.", "error")

            return redirect(url_for("share_document", document_id=document.id))

        # Get registered users except the document owner
        users = User.query.filter(
            User.id != current_user.id,
            User.is_active.is_(True)
        ).order_by(User.username).all()

        # Get users who already have access
        permissions = (
            db.session.query(DocumentPermission, User)
            .join(User, DocumentPermission.user_id == User.id)
            .filter(DocumentPermission.document_id == document.id)
            .order_by(User.username)
            .all()
        )

        return render_template(
            "share.html",
            document=document,
            users=users,
            permissions=permissions
        )

    @app.route(
        "/revoke/<int:document_id>/<int:user_id>",
        methods=["POST"]
    )
    @login_required
    def revoke_permission(document_id, user_id):

        # Only the document owner can revoke access
        document = Document.query.filter_by(
            id=document_id,
            owner_id=current_user.id,
            is_deleted=False
        ).first_or_404()

        permission = DocumentPermission.query.filter_by(
            document_id=document.id,
            user_id=user_id
        ).first()

        if permission is None:
            flash("Permission not found.", "error")
        else:
            try:
                # Record permission revocation in audit log
                record_audit(
                    actor_id=current_user.id,
                    document_id=document.id,
                    action="REVOKE",
                    outcome="SUCCESS",
                    details=(
                        f"Revoked access from user ID {permission.user_id}"
                    )
                )

                # Delete permission and save audit record together
                db.session.delete(permission)
                db.session.commit()

                flash("User access revoked successfully!", "success")
            except Exception:
                db.session.rollback()
                app.logger.exception("Permission revocation failed")
                flash("Unable to revoke access.", "error")

        return redirect(url_for("share_document", document_id=document.id))
    @app.route("/edit/<int:document_id>", methods=["GET", "POST"])
    @login_required
    def edit_document(document_id):

        document = Document.query.filter_by(
            id=document_id,
            is_deleted=False
        ).first_or_404()

        is_owner = document.owner_id == current_user.id

        permission = DocumentPermission.query.filter_by(
            document_id=document.id,
            user_id=current_user.id,
            can_edit=True
        ).first()

        if not is_owner and permission is None:
            abort(403)

        if request.method == "POST":

            new_title = request.form.get("title", "").strip()

            if not new_title:
                flash("Document title cannot be empty.", "error")

            elif len(new_title) > 200:
                flash("Document title is too long.", "error")

            else:
                document.title = new_title

                try:
                    db.session.commit()
                    flash("Document updated successfully!", "success")
                    return redirect(url_for("documents"))

                except Exception:
                    db.session.rollback()
                    app.logger.exception("Document update failed")
                    flash("Unable to update document.", "error")

        return render_template(
            "edit.html",
            document=document
        )
    # Database check for local development
    @app.route("/db-check")
    def db_check():
        try:
            db.session.execute(text("SELECT 1"))
            return {"database": "connected successfully"}
        except Exception:
            app.logger.exception("Database connection failed")
            return {"database": "connection failed"}, 500

    @app.route("/admin/audit")
    @login_required
    def admin_audit():

        # Only administrators can view audit logs
        if current_user.role != "admin":
            abort(403)

        logs = AuditLog.query.order_by(
            AuditLog.id.desc()
        ).limit(200).all()

        return render_template(
            "admin_audit.html",
            logs=logs
        )

    @app.route("/admin/audit/verify")
    @login_required
    def verify_audit():

        if current_user.role != "admin":
            abort(403)

        is_valid, failed_log_id = verify_audit_chain()

        return render_template(
            "audit_integrity.html",
            is_valid=is_valid,
            failed_log_id=failed_log_id
        )
    return app

app = create_app()
if __name__ == "__main__":
    app.run(debug=True)
