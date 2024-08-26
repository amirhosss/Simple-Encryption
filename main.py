import os
import base64
import getpass

import typer
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = typer.Typer(rich_markup_mode=None, pretty_exceptions_enable=False)


@app.command(help="Encrypt your data and make a file output")
def encrypt(iterations: int = 480_000):
    data = getpass.getpass("Please enter you data: ").rstrip()
    password = getpass.getpass("Enter your password for encryption: ").rstrip()
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


@app.command(help="Decrypt your data and print data in stdout")
def decrypt(file_name: str = "encrypted-data.txt", iterations: int = 480_000):
    password = getpass.getpass("Enter your password: ")
    password = bytes(password, "utf-8")

    try:
        with open(file_name, "rb") as file:
            salt = file.readline().rstrip()
            encrypted_data = file.readline()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))

            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            print("Successful. Your data is:", str(decrypted_data, "utf-8"), sep="\n")
    except FileNotFoundError as e:
        print(f"The file '{file_name}' not found. {e}")
    except Exception as e:
        print(
            f"Wrong password or corrupted data. Please check your password or iterations. {e}"
        )


if __name__ == "__main__":
    app()
