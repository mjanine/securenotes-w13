# SecureNotes API — Week 13 Security Lab (Student Starter)

A tiny notes service built with FastAPI. It runs, but it is **not secure**.
Your job: find the planted security bugs, fix them, and pass peer review.

## Setup
```bash
python -m venv venv
# Windows:  venv\Scripts\activate
# macOS/Linux:  source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000/docs to try the API.

## What's in here
- `app/main.py` — the whole app (one file, on purpose, so it is easy to review)
- `FINDINGS.md` — the worksheet you fill in as you hunt
- the app starts with 3 seeded users: `admin / admin123`, `alice / alicepass`, `bob / bobpass`

## Your job
See the lab handout. In short:
1. Find each security bug and record it in `FINDINGS.md` (what, where, which OWASP risk).
2. Fix it in `app/main.py` — without breaking register / login / notes.
3. Swap with a partner and peer-review their fixes using the checklist.

Do not add heavy libraries. Everything here can be fixed with FastAPI +
the Python standard library (`hashlib`, `hmac`, `secrets`, `time`).

## Part C — push to GitHub for peer review
After fixing, you'll push this project to a **public GitHub repo** and open a
**pull request** (`security-fixes` → `main`) so another pair can review your
changes as a diff. See the lab handout (Part C) for the exact git commands.

- Commit the **original** starter first, then your fixes on a `security-fixes` branch.
- A `.gitignore` is already included — do **not** commit `venv/` or `__pycache__/`.
- In the PR description, list the 6 bugs and their OWASP codes.
