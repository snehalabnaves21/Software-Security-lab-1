import os
import re
import hmac
import sqlite3
import secrets
import string
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_NAME = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "passwords.db"
)


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
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

    if re.search(
        r"012|123|234|345|456|567|678|789|"
        r"987|876|765|654|543|432|321|210",
        password
    ):
        return False

    if username and password.casefold() == username.casefold():
        return False

    return True


def make_hash(password):
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000
    )
    return salt, password_hash


def verify_password(password, salt, saved_hash):
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000
    )
    return hmac.compare_digest(password_hash, saved_hash)


def generate_password(username, length=12):
    if length != 12:
        raise ValueError("Password length must be 12.")

    characters = string.ascii_letters + string.digits + string.punctuation

    while True:
        password = "".join(
            secrets.choice(characters) for _ in range(length)
        )

        if check(username, password):
            return password


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Password Service is running",
        "routes": ["/generate", "/register", "/verify"]
    })


@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()

    if not username:
        return jsonify({"error": "Username is required"}), 400

    password = generate_password(username)
    return jsonify({"password": password}), 200


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "error": "Username and password are required"
        }), 400

    if not check(username, password):
        return jsonify({
            "error": "Password does not meet the requirements"
        }), 400

    salt, password_hash = make_hash(password)

    try:
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute(
                """
                INSERT INTO users (username, salt, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, salt, password_hash)
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

    return jsonify({
        "message": "User registered successfully",
        "username": username
    }), 201


@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    with sqlite3.connect(DB_NAME) as conn:
        row = conn.execute(
            "SELECT salt, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if row is None:
        return jsonify({"valid": False, "message": "User not found"}), 404

    valid = verify_password(password, row[0], row[1])

    return jsonify({
        "valid": valid,
        "message": "Password is correct" if valid else "Password is incorrect"
    }), 200


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001, debug=False)