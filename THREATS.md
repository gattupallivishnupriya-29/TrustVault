# TrustVault – Security Threat Model

## 1. Introduction

TrustVault is a secure document management system designed to protect confidential documents through authentication, role-based access control, permission management and audit logging.

## 2. Assets to Protect

- User accounts and passwords.
- Uploaded documents.
- Document ownership information.
- Document permissions.
- Audit logs.
- Database credentials and application secret key.

## 3. Potential Threats and Mitigations

### Threat 1: Unauthorized Document Access

Risk:
A user may try to access another user's documents without permission.

Mitigation:
- Authentication is required.
- Server-side authorization checks are performed.
- Document owners and authorized users are allowed access.
- Unauthorized download attempts are logged.

### Threat 2: Unauthorized Document Modification

Risk:
A viewer may try to edit a document without permission.

Mitigation:
- Only document owners and users with edit permission can edit documents.
- Unauthorized edit attempts are rejected.

### Threat 3: Permission Misuse

Risk:
A user may retain access after their permission is revoked.

Mitigation:
- Owners can grant and revoke permissions.
- Access is checked against current database permissions.
- Revoked access is rejected immediately in testing.

### Threat 4: Malicious File Upload

Risk:
An attacker may upload an unwanted or unsupported file.

Mitigation:
- Allowed file extensions are checked.
- File size is limited to 10 MB.
- Secure filenames and random storage keys are used.
- Uploaded documents are stored in private storage.

### Threat 5: Password and Credential Exposure

Risk:
Database credentials or application secrets may be exposed.

Mitigation:
- Environment variables are used for sensitive configuration.
- `.env` is excluded through `.gitignore`.
- Passwords are handled through the authentication system.

### Threat 6: Audit Log Tampering

Risk:
An attacker may modify audit records to hide suspicious activity.

Mitigation:
- Audit records are linked using cryptographic hashes.
- HMAC-SHA256 is used for integrity verification.
- The system records important successful and denied actions.

### Threat 7: Unauthorized Document Deletion

Risk:
A user may attempt to delete documents they do not own.

Mitigation:
- Only owners and administrators can delete documents.
- Soft deletion is used.
- Deleted documents are hidden from normal document listings.
- Downloading a deleted document is rejected.

## 4. Known Limitations

- The current audit verifier checks entries after checkpoint ID 10. Older entries have not been fully verified.
- The audit hash mechanism does not prevent tampering by an attacker who can modify the database and access the application secret key.
- Soft deletion hides documents but does not physically erase their stored files.
- Automated security testing and production deployment require further verification.

## 5. Future Improvements

- Add comprehensive automated authorization tests.
- Store audit checkpoints outside the application database.
- Implement stronger session and account security.
- Add secure backup and recovery.
- Introduce monitoring and alerting for suspicious activity.
- Perform security testing before production deployment.

## 6. Conclusion

TrustVault implements authentication, role-based access control, document permissions, private file storage and audit logging to improve document security. Further testing and security improvements are necessary before production use.