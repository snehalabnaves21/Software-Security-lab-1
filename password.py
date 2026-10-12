import requests

url = "http://127.0.0.1:5001"

username = input("Enter username: ").strip()

if not username:
    print("Username cannot be empty")
else:
    response = requests.post(
        url + "/generate",
        json={"username": username}
    )

    if response.status_code != 200:
        print(response.json())
    else:
        password = response.json()["password"]
        print("Generated password:", password)

        response = requests.post(
            url + "/register",
            json={"username": username, "password": password}
        )

        if response.status_code == 201:
            result = response.json()
            print("Username saved:", username)
            print("Password hash:", result["password_hash"])

            response = requests.post(
                url + "/verify",
                json={"username": username, "password": password}
            )
            print(response.json())
        else:
            print(response.json())