# TrustVault – Secure Document Management System

## Project Description
TrustVault is a secure document management system developed using Python and Flask. It allows users to upload, organize, search, download and share documents with role-based access control.

## Technologies Used
- Python
- Flask
- MySQL
- Flask-SQLAlchemy
- HTML
- CSS
- Bootstrap (if used in the interface)

## User Roles
1. Admin – Manages and monitors system activity.
2. Owner – Uploads and manages documents and grants access.
3. Viewer – Views and downloads documents when permission is granted.

## Main Features
- User registration and login.
- Role-based access control.
- Secure document upload and download.
- Document search and organization.
- Read and edit permissions.
- Grant and revoke document access.
- Audit logging of important activities.
- Audit integrity verification.
- Soft deletion of documents.

## Security Features
- Server-side authorization checks.
- Restricted document access.
- File type and size validation.
- Private document storage.
- Audit logging of successful and denied actions.
- Password-based authentication.

## Installation

1. Clone the repository:

   git clone https://github.com/gattupallivishnupriya-29/TrustVault.git

2. Open the project folder.

3. Create a virtual environment:

   python -m venv .venv

4. Activate it:

   .venv\Scripts\activate

5. Install dependencies:

   pip install -r requirements.txt

6. Configure the required environment variables in a local .env file.

7. Create the MySQL database and configure its connection.

8. Initialize the database tables:

   python create_tables.py

9. Run the application using the startup command configured in app.py.

## Project Repository
https://github.com/gattupallivishnupriya-29/TrustVault