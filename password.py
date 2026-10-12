
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

            entered = input("Enter password to check: ")

            response = requests.post(
                url + "/verify",
                json={"username": username, "password": entered}
            )

            result = response.json()
            print(result["message"])

        else:
            print(response.json())
