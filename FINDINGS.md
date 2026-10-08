

# Vulnerability Findings — Sola, Mariella Janine & Torreno, Lerrica Jeremy

There are **6** security bugs planted in `app/main.py`. Fill one row per bug.

| # | OWASP 2025                                     | Where                     | Attacker Abuse                         | Fix                                  |
| - | ---------------------------------------------- | ------------------------- | -------------------------------------- | ------------------------------------ |
| 1 | A03 – Injection                                | `/login`                  | Uses SQL input to bypass login.        | Use parameterized queries.           |
| 2 | A02 – Cryptographic Failures                   | DB & `/login`             | Steals plaintext passwords.            | Hash passwords with PBKDF2 and salt. |
| 3 | A01 – Broken Access Control                    | `/notes/{id}`             | Changes ID to view others' notes.      | Check note ownership.                |
| 4 | A05 – Security Misconfiguration                | Exception handler         | Causes errors to reveal stack traces.  | Return generic error messages.       |
| 5 | A01 – Broken Access Control                    | `/admin/users`            | Bypasses the admin check.              | Fix the authorization check.         |
| 6 | A07 – Identification & Authentication Failures | `current_user` / `/login` | Guesses user IDs to impersonate users. | Use signed authentication tokens.    |

## Reflection (3–4 sentences)

SQL Injection would likely cause the most damage in a real application. An attacker could bypass authentication and access or modify sensitive database information. It could potentially expose many users' accounts and private data. Therefore, preventing SQL Injection is critical for protecting the entire application.
