import requests

url = "http://127.0.0.1:5001"
username = input("Enter username: ").strip()
r = requests.post(url + "/generate", json={"username": username})
if r.status_code != 200:
    raise SystemExit(r.json())
password = r.json()["password"]
print("Generated password:", password)

r = requests.post(url + "/register", json={"username": username, "password": password})
if r.status_code != 201:
    raise SystemExit(r.json())
print("Username saved:", username)
print("Password hash:", r.json()["password_hash"])
entered = input("Enter password to check: ")
r = requests.post(url + "/verify", json={"username": username, "password": entered})
print(r.json()["message"])
