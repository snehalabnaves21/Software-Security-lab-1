import os, re, ctypes, sqlite3, secrets, hashlib, hmac, platform, yaml
from flask import Flask, request, jsonify

app = Flask(__name__)
here = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(here, "passwords.db")
ITERATIONS = 600_000
lib_name = "libpassgen.dylib" if platform.system() == "Darwin" else "libpassgen.so"
lib = ctypes.CDLL(os.path.join(here, lib_name))
lib.gen_password.argtypes = [ctypes.c_char_p, ctypes.c_int]
config = yaml.safe_load(open(os.path.join(here, "req.yaml")))["password"]
def get_json():
    data = request.get_json(silent=True) or {}
    return data.get("username", "").strip(), data.get("password", "")

def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITERATIONS)

@app.route("/")
def home():
    return "Password Service is running!"

@app.post("/generate")
def generate():
    username, _ = get_json()
    if not username:
        return jsonify(error="Enter username"), 400

    for _ in range(1000):                       
        buf = ctypes.create_string_buffer(config["length"] + 1)
        lib.gen_password(buf, config["length"])
        pw = buf.value.decode()
        if all(re.search(r["pattern"].replace("{username}", re.escape(username)), pw)
               for r in config["rules"]):
            return jsonify(password=pw)
    return jsonify(error="Generation failed"), 500


@app.post("/register")
def register():
    username, pw = get_json()
    if not username or not pw:
        return jsonify(error="Username and password required"), 400

    broken = [r["message"] for r in config["rules"]
              if not re.search(r["pattern"].replace("{username}", re.escape(username)), pw)]
    if broken:
        return jsonify(error="Password rules not satisfied", broken_rules=broken), 400

    salt = secrets.token_bytes(16)
    hashed = hash_pw(pw, salt)
    try:
        with sqlite3.connect(DB) as db:
            db.execute("INSERT INTO users VALUES (?, ?, ?)", (username, salt, hashed))
    except sqlite3.IntegrityError:
        return jsonify(error="Username already exists"), 409
    return jsonify(message="User registered successfully",
                   username=username, password_hash=hashed.hex()), 201


@app.post("/verify")
def verify():
    username, pw = get_json()
    with sqlite3.connect(DB) as db:
        row = db.execute("SELECT salt, password_hash FROM users WHERE username=?",
                         (username,)).fetchone()
    if row is None:
        return jsonify(valid=False, message="User not found"), 404

    ok = hmac.compare_digest(hash_pw(pw, row[0]), row[1])   
    return jsonify(valid=ok,
                   message="Password is correct" if ok else "Password is incorrect")


if __name__ == "__main__":
    with sqlite3.connect(DB) as db:
        db.execute("CREATE TABLE IF NOT EXISTS users "
                   "(username TEXT PRIMARY KEY, salt BLOB, password_hash BLOB)")
    app.run(host="127.0.0.1", port=5001)