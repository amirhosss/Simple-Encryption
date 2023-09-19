import os
import base64

import typer
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = typer.Typer()


@app.command()
def encrypt(data: str, password: str, iterations: int = 480_000):
    password = bytes(password, "utf-8")
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    f = Fernet(key)
    encrypted_data = f.encrypt(bytes(data, "utf-8"))

    with open("encrypted-data.txt", "wb") as file:
        file.writelines([salt, b"\n", encrypted_data])


@app.command()
def decrypt(password: str, iterations: int = 480_000):
    password = bytes(password, "utf-8")
    with open("encrypted-data.txt", "rb") as file:
        salt = file.readline().rstrip()
        encrypted_data = file.readline()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    f = Fernet(key)

    try:
        decrypted_data = f.decrypt(encrypted_data)
        print("Successful. Your data is:", str(decrypted_data, "utf-8"), sep="\n")
    except Exception:
        print(
            f"Wrong password or corrupted data. Please check your password or iterations"
        )


if __name__ == "__main__":
    app()
