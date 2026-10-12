import secrets
import string
import hashlib
import hmac
import re
def check(username, password):
    if len(password) != 12:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c in string.punctuation for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if re.search(r"012|123|234|345|456|567|678|789|987|876|765|654|543|432|321|210", password):
        return False
    if username and password.casefold() == username.casefold():
        return False
    return True


def generate_password(username):
    chars = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(chars) for _ in range(12))
        if check(username, password):
            return password


def make_hash(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 600000
    )
    return salt, digest


def verify_password(password, salt, saved_hash):
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 600000
    )
    return hmac.compare_digest(digest, saved_hash)


def main():
    print("=== Password Service ===")
    username = input("Enter username: ").strip()

    if not username:
        print("Username cannot be empty.")
        return

    password = generate_password(username)
    print("Generated password:", password)

    salt, saved_hash = make_hash(password)

    if verify_password(password, salt, saved_hash):
        print("Password verification successful.")
    else:
        print("Password verification failed.")

if __name__ == "__main__":
    main()