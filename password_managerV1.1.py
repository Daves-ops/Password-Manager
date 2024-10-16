import os
from cryptography.fernet import Fernet
import getpass
import logging
import re

# Setup logging
logging.basicConfig(filename='password_manager.log', level=logging.INFO, 
                    format='%(asctime)s - %(message)s')

# Generate or load the encryption key
def load_key():
    # Load the secret.key file if it exists; otherwise, generate and save a new key
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    else:
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
    return key

# Encrypt the password
def encrypt_password(password, key):
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password

# Decrypt the password
def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    decrypted_password = f.decrypt(encrypted_password).decode()
    return decrypted_password

# Check the strength of the password
def check_password_strength(password):
    if len(password) < 8:
        return "Weak"
    if not re.search("[a-z]", password):
        return "Weak"
    if not re.search("[A-Z]", password):
        return "Weak"
    if not re.search("[0-9]", password):
        return "Weak"
    if not re.search("[!@#$%^&*(),.?\":{}|<>]-", password):
        return "Weak"
    return "Strong"

# Add a new password
def add_password(key):
    service = input("Enter the service name: ")
    username = input("Enter your username for this service: ")
    password = getpass.getpass("Enter your password: ")
    
    strength = check_password_strength(password)
    print(f"Password strength: {strength}")
    
    encrypted_password = encrypt_password(password, key)
    
    # Save to file
    with open("passwords.txt", "a") as file:
        file.write(f"{service},{username},{encrypted_password.decode()}\n")
    
    logging.info(f"Password added for service: {service}")

# Retrieve a password for a service
def retrieve_password(key):
    service = input("Enter the service name: ")
    
    try:
        with open("passwords.txt", "r") as file:
            for line in file:
                stored_service, stored_username, stored_password = line.strip().split(",")
                if stored_service.lower() == service.lower():
                    decrypted_password = decrypt_password(stored_password.encode(), key)
                    print(f"Service: {stored_service}\nUsername: {stored_username}\nPassword: {decrypted_password}")
                    logging.info(f"Password retrieved for service: {service}")
                    return
        print("Service not found.")
    except FileNotFoundError:
        print("No passwords saved yet.")

# View all saved services (without showing passwords)
def view_services():
    try:
        with open("passwords.txt", "r") as file:
            print("Saved services:")
            for line in file:
                service = line.split(",")[0]
                print(service)
        logging.info("Viewed all saved services.")
    except FileNotFoundError:
        print("No passwords saved yet.")

# Backup passwords to a different file
def backup_passwords():
    try:
        backup_file = "passwords_backup.txt"
        with open("passwords.txt", "r") as original_file:
            with open(backup_file, "w") as backup:
                backup.write(original_file.read())
        print(f"Passwords backed up to {backup_file}")
        logging.info("Passwords backed up.")
    except FileNotFoundError:
        print("No passwords to back up.")

# Restore passwords from a backup file
def restore_passwords():
    try:
        backup_file = "passwords_backup.txt"
        with open(backup_file, "r") as backup:
            with open("passwords.txt", "w") as original_file:
                original_file.write(backup.read())
        print("Passwords restored from backup.")
        logging.info("Passwords restored from
