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

backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryption_key = 0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

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

window.title("Password Vault")

def HashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash

def RegisterScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x190")

    label_create = Label(window, text="Create Master Password")
    label_create.config(anchor=CENTER)
    label_create.pack(pady=(10, 0))

    password = Entry(window, width=20, show="*")
    password.pack()
    password.focus()

    label_confirm = Label(window, text="Re-enter Password")
    label_confirm.pack()

    password_confirm = Entry(window, width=20, show="*")
    password_confirm.pack()
    password_confirm.focus()

    label_status = Label(window)
    label_status.pack()

    def SavePassword():
        if password.get() == password_confirm.get():
            delete_old_masterpassword = "DELETE FROM masterpassword WHERE id = 1"

            cursor.execute(delete_old_masterpassword)

            hashed_password = HashPassword(password.get().encode('utf-8'))
            key = str(uuid.uuid4().hex)
            recovery_key = HashPassword(key.encode('utf-8'))

            global encryption_key
            encryption_key = base64.urlsafe_b64encode(kdf.derive(password.get().encode()))

            insert_password = """
                INSERT INTO masterpassword(password, recovery_key)
                VALUES(?, ?);
            """
            cursor.execute(insert_password, ((hashed_password), (recovery_key)))
            db.commit()

            RecoveryScreen(key)
        else:
            password.delete(0, 'end')
            password_confirm.delete(0, 'end')
            label_status.config(text="Passwords do not match")

    button = Button(window, text="Save", command=SavePassword)
    button.pack(pady=10)

def RecoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x190")

    label_savekey = Label(window, text="Save this key to be able to recover account")
    label_savekey.config(anchor=CENTER)
    label_savekey.pack(pady=(10, 0))

    label_key = Label(window, text=key)
    label_key.config(anchor=CENTER)
    label_key.pack()

    def CopyKey():
        pyperclip.copy(label_key.cget("text"))

    button_copy = Button(window, text="Copy Key", command=CopyKey)
    button_copy.pack(pady=10)

    def Done():
        PasswordVault()

    button_done = Button(window, text="Done", command=Done)
    button_done.pack(pady=10)

def ResetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x190")

    label_savekey = Label(window, text="Enter Recovery Key")
    label_savekey.config(anchor=CENTER)
    label_savekey.pack(pady=(10, 0))

    recovery_key = Entry(window, width=20)
    recovery_key.pack()
    recovery_key.focus()

    label_key = Label(window)
    label_key.config(anchor=CENTER)
    label_key.pack()

    def GetRecoveryKey():
        recovery_key_check = HashPassword(str(recovery_key.get()).encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND recovery_key = ?", [(recovery_key_check)])
        return cursor.fetchall()

    def CheckRecoveryKey():
        checked = GetRecoveryKey()

        if checked:
            RegisterScreen()
        else:
            recovery_key.delete(0, 'end')
            label_key.config(text="Wrong Key")

    button_check_key = Button(window, text="Check Recovery Key", command=CheckRecoveryKey)
    button_check_key.pack(pady=10)

def LoginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x230")

    label_login = Label(window, text="Enter Master Password")
    label_login.config(anchor=CENTER)
    label_login.pack(pady=(10, 0))

    password = Entry(window, width=20, show="*")
    password.pack()
    password.focus()

    label_status = Label(window)
    label_status.config(anchor=CENTER)
    label_status.pack(side=TOP)

    def GetMasterPassword():
        check_hashed_password = HashPassword(password.get().encode('utf-8'))

        global encryption_key
        encryption_key = base64.urlsafe_b64encode(kdf.derive(password.get().encode()))

        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?;", [(check_hashed_password)])
        return cursor.fetchall()

    def CheckPassword():
        match = GetMasterPassword()

        if match:
            PasswordVault()
        else:
            password.delete(0, 'end')
            label_status.config(text="Wrong Password")

    def ResetPassword():
        ResetScreen()

    button_submit = Button(window, text="Submit", command=CheckPassword)
    button_submit.pack(pady=5)

    button_reset = Button(window, text="Reset Password", command=ResetPassword)
    button_reset.pack(pady=5)

def PasswordVault():
    for widget in window.winfo_children():
        widget.destroy()

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

    window.geometry("850x350")

    label = Label(window, text="Password Vault")
    label.grid(column=1)

    button_add_entry = Button(window, text="+", command=AddEntry)
    button_add_entry.grid(column=1, pady=10)

    label_website = Label(window, text="Website")
    label_website.grid(row=2, column=0, padx=80)

    label_username = Label(window, text="Username")
    label_username.grid(row=2, column=1, padx=80)

    label_password = Label(window, text="Password")
    label_password.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if (len(array) == 0):
                break

            label_table_website = Label(window, text=(decrypt(array[i][1], encryption_key)), font=("Helvetica", 12))
            label_table_website.grid(column=0, row=i+3)

            label_table_username = Label(window, text=(decrypt(array[i][2], encryption_key)), font=("Helvetica", 12))
            label_table_username.grid(column=1, row=i+3)

            label_table_password = Label(window, text=(decrypt(array[i][3], encryption_key)), font=("Helvetica", 12))
            label_table_password.grid(column=2, row=i+3)

            button_delete = Button(window, text="Delete", command=partial(RemoveEntry, array[i][0]))
            button_delete.grid(column=3, row=i+3, pady=10)

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