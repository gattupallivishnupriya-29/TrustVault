# TrustVault – AI Prompt and Development Log

This document records the AI-assisted development process, problems encountered, corrections made and related Git commits.

## Entry 1 – Authentication and Role-Based Access Control

**Date:** November 6, 2026

**Prompt asked:**
Help me implement authentication and role-based access control for admin, owner and viewer roles in my TrustVault project.

**What AI produced:**
Guidance for Flask authentication, user roles and server-side authorization checks.

**What was wrong:**
Access control needed to be checked on the server-side routes, not just hidden in the user interface.

**What I did instead:**
Implemented role checks in protected routes and tested access using different user roles.

**Related code snapshot commit:**
https://github.com/gattupallivishnupriya-29/TrustVault/commit/5f40afe

---

## Entry 2 – Secure Document Upload

**Date:** November 6, 2026

**Prompt asked:**
Help me implement secure document upload with file validation and private storage.

**What AI produced:**
Guidance for file extension validation, file size restrictions, secure filenames and database records.

**What was wrong:**
Saving a file and creating its database record needed safe error handling to avoid leaving unwanted files behind if database operations failed.

**What I did instead:**
Implemented upload validation, random storage keys, private file storage and cleanup when database operations fail. Tested document upload.

**Related code snapshot commit:**
https://github.com/gattupallivishnupriya-29/TrustVault/commit/5f40afe

---

## Entry 3 – Document Permission Grant and Revocation

**Date:** November 7, 2026

**Prompt asked:**
Help me implement document sharing with read and edit permissions, including permission revocation.

**What AI produced:**
Guidance for granting, updating and revoking document permissions.

**What was wrong:**
A user whose permission had been revoked must not continue accessing the document.

**What I did instead:**
Tested permission granting, revocation and viewer access after revocation. Confirmed that revoked access returned HTTP 403.

**Related code snapshot commit:**
https://github.com/gattupallivishnupriya-29/TrustVault/commit/5f40afe

---

## Entry 4 – Audit Logging and Integrity Verification

**Date:** November 7, 2026

**Prompt asked:**
Help me implement audit logging and cryptographic integrity verification for TrustVault.

**What AI produced:**
Guidance for recording audit events and linking records using HMAC-SHA256 hashes.

**What was wrong:**
The initial verification failed because MySQL DATETIME precision differed from the timestamp precision used when creating the hashes.

**What I did instead:**
Used a legacy checkpoint at audit record ID 10 and verified subsequent records. Confirmed that a new audit record passed verification. Documented that older records remain unverified.

**Related code snapshot commit:**
https://github.com/gattupallivishnupriya-29/TrustVault/commit/5f40afe

---

## Entry 5 – Soft Deletion and Unauthorized Access Prevention

**Date:** November 8, 2026

**Prompt asked:**
Help me implement document deletion without immediately removing the document record from the database.

**What AI produced:**
Guidance for soft deletion using is_deleted and deleted_at fields.

**What was wrong:**
Deleting records permanently could make it harder to preserve document history and audit references.

**What I did instead:**
Implemented soft deletion, hid deleted documents from normal listings and blocked downloads of deleted documents. Tested that the old download URL returned HTTP 404.

**Related code snapshot commit:**
https://github.com/gattupallivishnupriya-29/TrustVault/commit/5f40afe

---

## Development Note

The entries above record the actual AI-assisted discussions and development work.

The linked commit 5f40afe is the initial committed source-code snapshot, created on November 8, 2026. It is not a separate historical commit for each feature.

Later documentation commits were created separately.