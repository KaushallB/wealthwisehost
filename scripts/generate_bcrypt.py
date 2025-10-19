#!/usr/bin/env python3
"""Generate a bcrypt hash for a password to insert an initial user into the DB.
Usage:
    python scripts/generate_bcrypt.py your-password
"""
import sys
from flask_bcrypt import Bcrypt
from flask import Flask

app = Flask(__name__)
bc = Bcrypt(app)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python scripts/generate_bcrypt.py <password>')
        sys.exit(2)
    pw = sys.argv[1]
    h = bc.generate_password_hash(pw).decode('utf-8')
    print(h)
