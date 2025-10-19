Pella.app deployment instructions for WealthWise

This file contains minimal changes and environment variables needed to deploy the Flask app to pella.app (or similar Flask-friendly hosts).

1) Repo entry point
- Pella expects a `main.py` with an exported `app` object. I added `main.py` which imports `app` from `app.py` and runs it locally when executed.

2) Environment variables to set in Pella.app
Set these in the Pella UI under Environment Variables (production scope):

- DATABASE_URL
  postgres://avnadmin:AVNS_GEpX-9nll9E9yyK6ktj@wealthwise-kaushalbikram44-25e1.b.aivencloud.com:18768/defaultdb?sslmode=require

- SECRET_KEY
  (Use a long random string; you can reuse your old key or create a new one)

- EMAIL_USER
  wealth.wisee.25@gmail.com

- EMAIL_PASS
  hoth zciu atfz cfup

- GEMINI_API_KEY
  AIzaSyDWbUdkSHa3H6bPyJ6XmwD8pXIdxV717Cw

3) Start/Run command
- Use the following start command (pella will use the provided Python runtime):

pip install -r requirements.txt && gunicorn app:app -b 0.0.0.0:$PORT

4) Files I added/changed
- Added `main.py` — simple WSGI entrypoint so pella.app can import `app` from `app.py`.

5) Additional notes
- Make sure `aiven_create.sql` has already been executed on your Aiven DB (you already ran it).
- Do not commit any real secrets to git. Use Pella's environment variables UI to store secrets.

6) Quick smoke test (after deploy)
- Open the pella URL and try to register / login. If there is a DB error, check the pella logs for psycopg2 connection errors.

If you want, I can:
- Add a small healthcheck route (e.g., `/health`) that returns 200 OK so pella can use it.
- Add a tiny systemd-like restart script or Procfile if pella requires it (check platform docs).

