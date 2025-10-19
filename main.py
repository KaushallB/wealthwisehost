import os

# Minimal WSGI entrypoint for hosting platforms (pella.app) that expect a
# `main.py` file with an `app` object. This simply imports the Flask `app`
# instance from `app.py` so the platform can serve it.

from app import app  # noqa: E402,F401


if __name__ == '__main__':
    # Local dev convenience: honor $PORT if set by the host
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
