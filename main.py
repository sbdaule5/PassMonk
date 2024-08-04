#!/usr/bin/env python3

import os
import sqlite3
from getpass import getpass
from base64 import b64encode

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding

from pyfzf.pyfzf import FzfPrompt

####################################### DATABASE INITIALIZATION ##################################################
try:
    dataDir = os.path.join(os.environ["XDG_DATA_HOME"], "passmonk")
except:
    dataDir = os.path.join(os.environ["HOME"], ".local/share/passmonk")
passFile = os.path.join(dataDir, "passwords.db")
try:
    os.makedirs(dataDir, exist_ok=True)
except:
    print(f"Failed to create directory {dataDir}, aborting...")
    exit(1)


conn = sqlite3.connect(passFile)
cursor = conn.cursor()

###################################### CREATE THE TABLE IF IT DOESN'T EXIST ######################################
cursor.execute('''
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        website TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
''')
conn.commit()

def encrypt(text: str, key: bytes) -> bytes:
    ############################## Generate a random IV (Initialization Vector) ###################################
    iv = os.urandom(16)

    #################################### PAD THE PLAINTEXT BEFORE ENCRYPTION ######################################
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()

    ######################## CREATE THE CIPHER OBJECT WITH CBC MODE AND THE GENERATED IV ##########################
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    ######################################### ENCRYPT THE PADDED DATA #############################################
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    ############################# RETURN THE IV CONCATENATED WITH THE CIPHERTEXT ##################################
    return iv + ciphertext

def decrypt(ciphertext: bytes, key: bytes) -> str:
    ########################### EXTRACT THE IV FROM THE FIRST 16 BYTES OF THE CIPHERTEXT ##########################
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    ######################### CREATE THE CIPHER OBJECT WITH CBC MODE AND THE EXTRACTED IV #########################
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    ########################################## DECRYPT THE CIPHERTEXT #############################################
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    ######################################### UNPAD THE DECRYPTED DATA ############################################
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    except ValueError:
        return "Invalid Master Password."

    ################################### RETURN THE UNPADDED DATA AS A STRING ######################################
    return unpadded_data.decode()

################################################## GENERATING KEY #################################################
def generate_key(master_password: str, salt : bytes = bytes(235230723)) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        length=32,
        salt=salt,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode())
    return key

########################################## FUNCTION FOR STORING PASSWORD ##########################################
def store_password(website: str, username: str, password: str, key: bytes) -> None:
    ########################################## GENERATE A RANDOM SALT #############################################
    salt = os.urandom(16)
    encrypted_password = encrypt(password, key)

    cursor.execute('INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)', (website, username, encrypted_password))
    conn.commit()

########################################### FUNCTION FOR GETTING PASSWORD ##########################################
def retrieve_password(website: str, username: str, key: bytes) -> str:
    print(f"website: {website}, username: {username}")
    cursor.execute('SELECT id, password FROM passwords WHERE website = ? AND username = ?', (website, username))
    result = cursor.fetchone()

    if result:
        id, encrypted_password = result
        decrypted_password = decrypt(encrypted_password, key)
        return decrypted_password
    else:
        return None

def check_master_pass(master_password : str) -> bool:
    cursor.execute('SELECT username,password FROM passwords WHERE website = "$$"')
    result = cursor.fetchone()
    if result is None:
        # This is being run for first time
        print("Welcome to PassMonk")
        salt = os.urandom(16)
        if salt == 235230723:
            raise Exception("Your are unlucky, try again")
        pass_hash = generate_key(master_password, salt)

        var_pass = getpass("Confirm master password: ")
        if var_pass != master_password:
            print("Two passwords do not match, try again...")
            return False

        cursor.execute('INSERT INTO passwords (website, username, password) VALUES ("$$", ?, ?)', (salt, b64encode(pass_hash).decode()))
        conn.commit()
        return True

    if result[1] == b64encode(generate_key(master_password, result[0])).decode():
        return True
    return False

def main():

    # Get the password
    valid_pass = False
    for _ in range(3):
        master_password = getpass("Enter master password to access the password store: ")
        # Verify the key using some method and throw error if it is wrong
        if check_master_pass(master_password):
            valid_pass = True
            break
        else:
            print("Incorrect password")
    if not valid_pass:
        print("Three failed attempts to enter the master password, exiting...")
        return

    key = generate_key(master_password)

    fzf = FzfPrompt()
    actions = fzf.prompt(['Retrieve Password', 'Store Password'], "--height ~40%")

    if not actions:
        print("Action not selected. Exiting.")
        return

    action = actions[0]
    if action == 'Store Password':
        website = input("Enter website: ")
        username = input("Enter username: ")
        password = getpass("Enter password: ")
        store_password(website, username, password, key)
    elif action == 'Retrieve Password':
        cursor.execute('SELECT website FROM passwords')
        result = cursor.fetchall()
        if len(result) == 1:
            print("No stored password found, aborting...")
            return
        website = fzf.prompt([r[0] for r in result if r[0] != "$$"], "--height ~40%")
        if not website:
            print("Website not selected, aborting...")
            return
        website = website[0]

        cursor.execute('SELECT username FROM passwords WHERE website = ?', ([website]))
        result = cursor.fetchall()
        username = ''
        if len(result) == 1:
            username = result[0][0]
            print(f"Username: {username}")
        elif len(result) == 0:
            raise Exception("Something went wrong...")
        else:
            username = fzf.prompt([r[0] for r in result], "--height ~40%")
            if not username:
                print("Username not selected, aborting...")
                return
            username = username[0]

        retrieved_password = retrieve_password(website, username, key)
        if retrieved_password:
            print(f"Retrieved Password: {retrieved_password}")
        else:
            print("Password not found.")
    else:
        print("Invalid action.")

if __name__ == "__main__":
    main()
