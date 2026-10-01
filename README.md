# Encryptron

A learning project for processing files in a web app built with Python, Flask, and SQLite. Users can register, sign in, process files with a password, and manage access permissions.

> **Prototype status:** This project implements a custom cipher for learning. It has not undergone a security audit and should not be used to protect sensitive data.

## What it does

- Account registration and login using Werkzeug password hashing.
- Session-based access to file-processing pages.
- Password-based file processing and `.enc` downloads.
- ZIP compression before the custom cipher transformation.
- SQLite tables for users, file records, and per-user access permissions.
- Routes for granting and revoking file access.

## Technology

Python · Flask · Werkzeug · SQLite · HTML · CSS

## Run locally

```sh
git clone https://github.com/varunpuskur/securefileutility.git
cd securefileutility
python3 -m venv .venv
source .venv/bin/activate
python -m pip install Flask
python -c "from app import init_db; init_db()"
python -m flask --app app run
```

On Windows, activate the environment with `.venv\Scripts\activate`.

Open http://127.0.0.1:5000 and register a local test account. Use disposable, non-sensitive sample files. The repository does not currently provide a dependency lockfile; these instructions are derived from the application imports and have not been run as part of this documentation update.

## Project structure

| Path | Purpose |
| --- | --- |
| `app.py` | Flask routes, account handling, database initialization, file permissions, and the `Encryptor` class |
| `templates/` | HTML pages for the application workflows |
| `static/` | Styles and other frontend assets |
| `utils/` | Additional utility files |
| `database.db` | SQLite database included in the repository |

The encryption route records a filename and owner, then returns the processed file as a download. The decryption route checks the database record and the signed-in user's permissions before processing the uploaded file.

## Limitations and next steps

- Replace the custom cipher with a reviewed authenticated-encryption implementation before considering real security use.
- Move the hardcoded Flask session secret into environment configuration.
- Add a dependency manifest, automated round-trip tests, and permission tests.
- Review upload limits, request validation, and database handling before deployment.

This repository demonstrates application workflows and learning progress; it does not claim production security.
