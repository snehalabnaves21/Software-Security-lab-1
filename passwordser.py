import os
import re
import ctypes
import sqlite3
import secrets
import string
import hashlib
import hmac
from flask import Flask, request, jsonify

app = Flask(__name__)

folder = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(folder, "passwords.db")
LIB_PATH = os.path.join(folder, "libpassgen.dylib")

lib = ctypes.CDLL(LIB_PATH)
lib.gen_password.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int]
lib.gen_password.restype = ctypes.c_int


def init_db():
    with sqlite3.connect(DB_NAME) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL
            )
        """)


def check(username, password):
    if len(password) != 12:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in string.punctuation for c in password):
        return False

    sequences = [
        "012", "123", "234", "345", "456", "567", "678", "789",
        "987", "876", "765", "654", "543", "432", "321", "210"
    ]

    if any(s in password for s in sequences):
        return False

    return password.casefold() != username.casefold()


def generate_password(username):
    for _ in range(1000):
        buf = ctypes.create_string_buffer(13)

        if lib.gen_password(buf, 12) != 0:
            raise RuntimeError("Password generation failed")

        password = buf.value.decode("ascii")

        if check(username, password):
            return password

    raise RuntimeError("Could not generate valid password")


def make_hash(password):
    salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 600000
    )
    return salt, hashed


def verify_password(password, salt, saved_hash):
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 600000
    )
    return hmac.compare_digest(hashed, saved_hash)


@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()

    if not username:
        return jsonify({"error": "Enter username"}), 400

    try:
        return jsonify({"password": generate_password(username)})
    except RuntimeError:
        app.logger.exception("Generation failed")
        return jsonify({"error": "Generation failed"}), 500


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if not check(username, password):
        return jsonify({"error": "Password rules not satisfied"}), 400

    salt, hashed = make_hash(password)

    try:
        with sqlite3.connect(DB_NAME) as db:
            db.execute(
                "INSERT INTO users VALUES (?, ?, ?)",
                (username, salt, hashed)
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

    return jsonify({
        "message": "User registered successfully",
        "username": username,
        "password_hash": hashed.hex()
    }), 201


@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    with sqlite3.connect(DB_NAME) as db:
        row = db.execute(
            "SELECT salt, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if row is None:
        return jsonify({"valid": False, "message": "User not found"}), 404

    valid = verify_password(password, row[0], row[1])

    return jsonify({
        "valid": valid,
        "message": "Password is correct" if valid else "Password is incorrect"
    })


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001, debug=False)