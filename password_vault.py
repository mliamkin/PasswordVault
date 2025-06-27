import sqlite3, hashlib
import uuid
import pyperclip
import base64
import os
from tkinter import *
from tkinter import simpledialog
from functools import partial
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Set up Tkinter backend
backend = default_backend()

# Salt for encryption
salt = b'2444'

# Set key derivation function
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

# Initialize encryption key
encryption_key = 0

# Encrypt message using key
def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

# Decrypt message using token
def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)

# Connect to database
with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

# Create master password table in database
cursor.execute("""
    CREATE TABLE IF NOT EXISTS masterpassword(
        id INTEGER PRIMARY KEY,
        password TEXT NOT NULL,
        recovery_key TEXT NOT NULL
    );
""")

# Create vault table in database
cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault(
        id INTEGER PRIMARY KEY,
        website TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    );
""")

# Create pop up
def PopUp(text):
    answer = simpledialog.askstring("input string", text)
    return answer

# Initiate Tkinter window
window = Tk()

# Set top title in Tkinter window as 'Password Vault'
window.title("Password Vault")

# Function to hash password with SHA256 algorithm
def HashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()
    return hash

# Function that creates registration screen for Password Vault app
def RegisterScreen():
    # Clear previous widgets and windows
    for widget in window.winfo_children():
        widget.destroy()

    # Set Tkinter window size
    window.geometry("250x190")

    # Create label for the master password input field
    label_create = Label(window, text="Create Master Password")
    label_create.config(anchor=CENTER)
    label_create.pack(pady=(10, 0))

    # Create input field for entering the master password
    password = Entry(window, width=20, show="*")
    password.pack()
    password.focus()

    # Create label for master password confirmation input field
    label_confirm = Label(window, text="Re-enter Password")
    label_confirm.pack()

    # Create input field for entering the master password confirmation
    password_confirm = Entry(window, width=20, show="*")
    password_confirm.pack()
    password_confirm.focus()

    # Create empty label to display error when master passwords do not match
    label_status = Label(window)
    label_status.pack()

    # Function to save master password into database when both inputs match
    def SavePassword():
        if password.get() == password_confirm.get():
            # Delete the old masterpassword if it exists
            delete_old_masterpassword = "DELETE FROM masterpassword WHERE id = 1"
            cursor.execute(delete_old_masterpassword)

            # Hash the entered master password
            hashed_password = HashPassword(password.get().encode('utf-8'))

            # Create a recovery key in case master password cannot be found
            key = str(uuid.uuid4().hex)
            recovery_key = HashPassword(key.encode('utf-8'))

            # Get the encryption key from the encoded hashed password using key derivation function
            global encryption_key
            encryption_key = base64.urlsafe_b64encode(kdf.derive(password.get().encode()))

            # Insert the hashed master password and recovery key into the master password table and commit to database
            insert_password = """
                INSERT INTO masterpassword(password, recovery_key)
                VALUES(?, ?);
            """
            cursor.execute(insert_password, ((hashed_password), (recovery_key)))
            db.commit()

            # Display screen displaying the recovery key for user to save it
            RecoveryScreen(key)
        else:
            # In case master password and confirm master password inputs do not match, clear inputs and display an error message
            password.delete(0, 'end')
            password_confirm.delete(0, 'end')
            label_status.config(text="Passwords do not match")

    # Create button to save password by calling the SavePassword function above when clicked
    button = Button(window, text="Save", command=SavePassword)
    button.pack(pady=10)

# Function to open window with recovery key for the user to save
def RecoveryScreen(key):
    # Clear previous widgets and windows
    for widget in window.winfo_children():
        widget.destroy()

    # Set Tkinter window size
    window.geometry("300x190")

    # Create label prompting the user to save the recovery key
    label_savekey = Label(window, text="Save this key to be able to recover account")
    label_savekey.config(anchor=CENTER)
    label_savekey.pack(pady=(10, 0))

    # Create label holding the recovery key value
    label_key = Label(window, text=key)
    label_key.config(anchor=CENTER)
    label_key.pack()

    # Function to copy the recovery key into the user's clipboard
    def CopyKey():
        pyperclip.copy(label_key.cget("text"))

    # Create button to save the recovery key by caling the CopyKey function above when clicked
    button_copy = Button(window, text="Copy Key", command=CopyKey)
    button_copy.pack(pady=10)

    # Function to open the Password Vault app by calling PasswordVault function
    def Done():
        PasswordVault()

    # Create button for when user is done with window by calling the Done function above when clicked
    button_done = Button(window, text="Done", command=Done)
    button_done.pack(pady=10)

# Function for user to reset the master password using the recovery key as input
def ResetScreen():
    # Clear previous widgets and windows
    for widget in window.winfo_children():
        widget.destroy()

    # Set Tkinter window size
    window.geometry("250x190")

    # Create label for recovery key input field
    label_savekey = Label(window, text="Enter Recovery Key")
    label_savekey.config(anchor=CENTER)
    label_savekey.pack(pady=(10, 0))

    # Create input field for the recovery key
    recovery_key = Entry(window, width=20)
    recovery_key.pack()
    recovery_key.focus()

    # Create empty label to display error when input recovery key is not valid
    label_key = Label(window)
    label_key.config(anchor=CENTER)
    label_key.pack()

    # Function to get the recovery key from the master password table in database
    def GetRecoveryKey():
        recovery_key_check = HashPassword(str(recovery_key.get()).encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND recovery_key = ?", [(recovery_key_check)])
        return cursor.fetchall()

    # Function to check the actual recovery key with the input recovery key
    def CheckRecoveryKey():
        # if the input recovery key matches the database, continue to registration screen, otherwise, clear inputs and display error
        checked = GetRecoveryKey()
        if checked:
            RegisterScreen()
        else:
            recovery_key.delete(0, 'end')
            label_key.config(text="Wrong Key")

    # Create button to check the recovery key by calling the CheckRecoveryKey function above when clicked
    button_check_key = Button(window, text="Check Recovery Key", command=CheckRecoveryKey)
    button_check_key.pack(pady=10)

# Function that creates Login screen for Password Vault app
def LoginScreen():
    # Clear previous widgets and windows
    for widget in window.winfo_children():
        widget.destroy()

    # Set Tkinter window size
    window.geometry("250x180")

    # Create label for entering master password to view passwords table
    label_login = Label(window, text="Enter Master Password")
    label_login.config(anchor=CENTER)
    label_login.pack(pady=(10, 0))

    # Create input field entering master password
    password = Entry(window, width=20, show="*")
    password.pack()
    password.focus()

    # Create empty label to show error when master password is not correct
    label_status = Label(window)
    label_status.config(anchor=CENTER)
    label_status.pack(side=TOP)

    # Function that gets the master password, compares it to the hashed master password input, and returns True if they match
    def GetMasterPassword():
        # Hash the master password input
        check_hashed_password = HashPassword(password.get().encode('utf-8'))

        # Get the encryption key using the key derivation function
        global encryption_key
        encryption_key = base64.urlsafe_b64encode(kdf.derive(password.get().encode()))

        # Check if the hashed master passwords matches the master password in the database
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?;", [(check_hashed_password)])
        return cursor.fetchall()

    # Function that checks if the master password is correct by calling the GetMasterPassword
    def CheckPassword():
        match = GetMasterPassword()

        # If there is a match, open the main app, otherwise, display an error message
        if match:
            PasswordVault()
        else:
            password.delete(0, 'end')
            label_status.config(text="Wrong Password")

    # Function that resets the password
    def ResetPassword():
        ResetScreen()

    # Create button for submitting master password and checking it
    button_submit = Button(window, text="Submit", command=CheckPassword)
    button_submit.pack(pady=5)

    # Create button for resetting master password
    button_reset = Button(window, text="Reset Password", command=ResetPassword)
    button_reset.pack(pady=5)

# Function that launches password vault
def PasswordVault():
    # Clear previous widgets and windows
    for widget in window.winfo_children():
        widget.destroy()

    # Set Tkinter window size
    window.geometry("850x350")

    # Function that 
    def AddEntry():
        text_website = "Website"
        text_username = "Username"
        text_password = "Password"

        website = encrypt(PopUp(text_website).encode(), encryption_key)
        username = encrypt(PopUp(text_username).encode(), encryption_key)
        password = encrypt(PopUp(text_password).encode(), encryption_key)

        insert_fields = """
            INSERT INTO vault(website,username,password)
            VALUES(?, ?, ?)
        """
        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        PasswordVault()

    def RemoveEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()

        PasswordVault()

    label = Label(window, text="Password Vault")
    label.grid(column=1, pady=20)

    button_add_entry = Button(window, text="+", command=AddEntry)
    button_add_entry.grid(column=1)

    label_website = Label(window, text="WEBSITE")
    label_website.grid(row=2, column=0, pady=20, padx=80)

    label_username = Label(window, text="USERNAME")
    label_username.grid(row=2, column=1, pady=20, padx=80)

    label_password = Label(window, text="PASSWORD")
    label_password.grid(row=2, column=2, pady=20, padx=80)

    cursor.execute("SELECT * FROM vault")
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if (len(array) == 0):
                break

            label_table_website = Label(window, text=(decrypt(array[i][1], encryption_key)), font=("Helvetica", 12))
            label_table_website.grid(column=0, row=i+3, pady=5)

            label_table_username = Label(window, text=(decrypt(array[i][2], encryption_key)), font=("Helvetica", 12))
            label_table_username.grid(column=1, row=i+3, pady=5)

            label_table_password = Label(window, text=(decrypt(array[i][3], encryption_key)), font=("Helvetica", 12))
            label_table_password.grid(column=2, row=i+3, pady=5)

            button_delete = Button(window, text="Delete", command=partial(RemoveEntry, array[i][0]))
            button_delete.grid(column=3, row=i+3, pady=5)

            i = i+1

            cursor.execute("SELECT * FROM vault")
            if (len(cursor.fetchall()) <= i):
                break

cursor.execute("SELECT * FROM masterpassword;")
existing_user = cursor.fetchall()

if existing_user:
    LoginScreen()
else:
    RegisterScreen()

window.mainloop()