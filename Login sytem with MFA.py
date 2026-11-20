import hashlib
import secrets
import pyotp
import getpass
import qrcode
import os

users = {}

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200000
    ).hex()


# REGISTER USER AND GENERATE QR CODE
def register():

    username = input("Create username: ")
    password = getpass.getpass("Create password: ")

    if not username or not password:
        print("Username and password cannot be empty.")
        return

    if username in users:
        print("Username already exists.")
        return

    salt = secrets.token_bytes(16)
    secret = pyotp.random_base32()

    users[username] = {
        "salt": salt,
        "password": hash_password(password, salt),
        "secret": secret
    }

    print("\nRegistration successful!")

    # Generate Google Authenticator setup URI
    totp = pyotp.TOTP(secret)

    uri = totp.provisioning_uri(
        name=username,
        issuer_name="Python MFA Security"
    )

    # Generate QR code
    qr = qrcode.make(uri)

    filename = "mfa_qr.png"
    qr.save(filename)

    print("\nQR code generated successfully!")
    print("QR Image:", os.path.abspath(filename))

    print("\nScan this QR code using Google Authenticator.")
    print("Manual setup key:", secret)

    print("\nIMPORTANT: Keep your MFA secret private.")


# LOGIN WITH MFA
def login():

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    user = users.get(username)

    if not user:
        print("Invalid username or password.")
        return

    password_hash = hash_password(
        password,
        user["salt"]
    )

    if not secrets.compare_digest(
        password_hash,
        user["password"]
    ):
        print("Invalid username or password.")
        return

    print("\nPassword verified!")

    # Verify Google Authenticator OTP
    totp = pyotp.TOTP(user["secret"])

    otp = input("Enter 6-digit Google Authenticator OTP: ").strip()

    if totp.verify(otp, valid_window=1):
        print("\nLogin successful!")
        print("MFA verification passed.")
        print("Welcome,", username)

    else:
        print("\nInvalid OTP.")
        print("Please check Google Authenticator.")


# MAIN MENU
print("================================")
print("    PYTHON MFA LOGIN SYSTEM")
print("================================")

while True:

    print("\n1. Register")
    print("2. Login")
    print("3. Exit")

    choice = input("\nSelect option: ")

    if choice == "1":
        register()

    elif choice == "2":
        login()

    elif choice == "3":
        print("Application closed.")
        break

    else:
        print("Invalid choice.")
