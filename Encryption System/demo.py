import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import smtplib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sqlite3

# Initialize the selected file path as None
selected_file_path = None

# Initialize the database
conn = sqlite3.connect('user_credentials.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT
    )
''')
conn.commit()

# AES encryption and decryption functions
def encrypt_aes(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return encrypted_data

def decrypt_aes(key, encrypted_data):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

def browse_file():
    global selected_file_path, file_path_label  # Declare file_path_label as global
    selected_file_path = filedialog.askopenfilename(title='Select Image')
    if file_path_label is not None:  # Check if file_path_label exists
        file_path_label.config(text='Selected File: ' + selected_file_path)

def perform_encryption():
    if selected_file_path is None:
        status_label.config(text='Please select a file first')
        return

    key = key_entry.get()
    if len(key) != 16:
        status_label.config(text='Key must be exactly 16 characters long')
        return

    try:
        with open(selected_file_path, 'rb') as fin:
            image = fin.read()

        encrypted_image = encrypt_aes(key.encode(), image)

        with open(selected_file_path, 'wb') as fout:
            fout.write(encrypted_image)

        status_label.config(text='Encryption Done...')
    except Exception as e:
        status_label.config(text='Error caught: ' + str(e))

def perform_decryption():
    if selected_file_path is None:
        status_label.config(text='Please select a file first')
        return

    key = key_entry.get()
    if len(key) != 16:
        status_label.config(text='Key must be exactly 16 characters long')
        return

    try:
        with open(selected_file_path, 'rb') as fin:
            encrypted_image = fin.read()

        decrypted_image = decrypt_aes(key.encode(), encrypted_image)

        with open(selected_file_path, 'wb') as fout:
            fout.write(decrypted_image)

        status_label.config(text='Decryption Done...')
    except Exception as e:
        status_label.config(text='Error caught: ' + str(e))
        if "padding" in str(e).lower():
            status_label.config(text='Decryption Error: Incorrect Key or Corrupted Data')

def send_email():
    sender_email = sender_email_entry.get()
    sender_password = sender_password_entry.get()
    receiver_email = receiver_email_entry.get()
    subject = subject_entry.get()
    message = message_text.get("1.0", "end-1c")

    try:
        if not sender_email or not sender_password or not receiver_email or not subject or not message or selected_file_path is None:
            messagebox.showerror("Error", "Please fill in all fields and attach a file.")
            return

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'plain'))

        file_name = os.path.basename(selected_file_path)

        with open(selected_file_path, "rb") as attachment:
            part = MIMEApplication(attachment.read(), Name=file_name)
            part['Content-Disposition'] = f'attachment; filename="{file_name}"'
            msg.attach(part)

        smtp_server = smtplib.SMTP('smtp.gmail.com', 587)
        smtp_server.starttls()
        smtp_server.login(sender_email, sender_password)
        smtp_server.sendmail(sender_email, receiver_email, msg.as_string())
        smtp_server.quit()
        messagebox.showinfo("Success", "Email sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def register_user():
    username = username_entry.get()
    password = password_entry.get()

    if not username or not password:
        messagebox.showerror("Registration Error", "Username and password are required.")
        return

    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    messagebox.showinfo("Registration Successful", "You have been registered successfully!")

def authenticate_and_start():
    username = username_entry.get()
    password = password_entry.get()

    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    if cursor.fetchone():
        # User authenticated, show the main application window
        auth_window.destroy()

        # Create the main GUI window
        window = tk.Tk()
        window.title('Email Sender & File Encryption/Decryption')
        window.geometry('800x400')  # Set GUI size

        # Create a notebook to switch between email sender and encryption/decryption tabs
        notebook = ttk.Notebook(window)
        notebook.pack(fill='both', expand=True)

        # Create email sender tab
        email_sender_frame = ttk.Frame(notebook)
        notebook.add(email_sender_frame, text='Email Sender')

        style = ttk.Style()
        style.configure('email.TFrame', background='#f0f0f0')
        email_sender_frame.configure(style='email.TFrame')

        # Colorful button style for email sender tab
        button_style_email_sender = ttk.Style()
        button_style_email_sender.configure('EmailSender.TButton', background='lightblue', foreground='black', padding=10)
        sender_email_label = tk.Label(email_sender_frame, text="Sender Email:")
        sender_email_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        global sender_email_entry  # Declare sender_email_entry as global
        sender_email_entry = tk.Entry(email_sender_frame)
        sender_email_entry.grid(row=0, column=1, padx=10, pady=5)

        sender_password_label = tk.Label(email_sender_frame, text="Password:")
        sender_password_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        global sender_password_entry  # Declare sender_password_entry as global
        sender_password_entry = tk.Entry(email_sender_frame, show="*")
        sender_password_entry.grid(row=1, column=1, padx=10, pady=5)

        receiver_email_label = tk.Label(email_sender_frame, text="Receiver Email:")
        receiver_email_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

        global receiver_email_entry  # Declare receiver_email_entry as global
        receiver_email_entry = tk.Entry(email_sender_frame)
        receiver_email_entry.grid(row=2, column=1, padx=10, pady=5)

        subject_label = tk.Label(email_sender_frame, text="Subject:")
        subject_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")

        global subject_entry  # Declare subject_entry as global
        subject_entry = tk.Entry(email_sender_frame)
        subject_entry.grid(row=3, column=1, padx=10, pady=5)

        message_label = tk.Label(email_sender_frame, text="Message:")
        message_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")

        global message_text  # Declare message_text as global
        message_text = tk.Text(email_sender_frame, height=5, width=40)
        message_text.grid(row=4, column=1, padx=10, pady=5)

        attach_button = ttk.Button(email_sender_frame, text="Attach File", command=browse_file, style='EmailSender.TButton')
        attach_button.grid(row=5, column=0, columnspan=2, padx=10, pady=5)

        global attachment_label  # Declare attachment_label as global
        attachment_label = tk.Label(email_sender_frame, text="Selected File: None")
        attachment_label.grid(row=6, column=0, columnspan=2, padx=10, pady=5)

        send_button = ttk.Button(email_sender_frame, text="Send Email", command=send_email, style='EmailSender.TButton')
        send_button.grid(row=7, column=0, columnspan=2, padx=10, pady=5)

        # Create encryption/decryption tab
        encryption_frame = ttk.Frame(notebook)
        notebook.add(encryption_frame, text='Encryption/Decryption')

        encryption_frame.configure(style='email.TFrame')

        # Colorful button style for encryption/decryption tab
        button_style_encryption = ttk.Style()
        button_style_encryption.configure('Encryption.TButton', background='lightgreen', foreground='black', padding=10)
        key_label = tk.Label(encryption_frame, text='Enter AES Key (16 characters):')
        key_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        global key_entry  # Declare key_entry as global
        key_entry = tk.Entry(encryption_frame, show='*')
        key_entry.grid(row=0, column=1, padx=10, pady=5)

        choose_file_button = ttk.Button(encryption_frame, text='Choose Image', command=browse_file, style='Encryption.TButton')
        choose_file_button.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

        encrypt_button = ttk.Button(encryption_frame, text='Encrypt', command=perform_encryption, style='Encryption.TButton')
        encrypt_button.grid(row=2, column=0, padx=10, pady=5)

        decrypt_button = ttk.Button(encryption_frame, text='Decrypt', command=perform_decryption, style='Encryption.TButton')
        decrypt_button.grid(row=2, column=1, padx=10, pady=5)

        global file_path_label, status_label  # Declare file_path_label and status_label as global
        file_path_label = tk.Label(window, text='Selected File: None', wraplength=400, bg='#f0f0f0')
        file_path_label.pack(pady=10)

        status_label = tk.Label(window, text='', fg='blue', bg='#f0f0f0')
        status_label.pack(pady=10)

        # Start the GUI event loop
        window.mainloop()
    else:
        messagebox.showerror("Authentication Error", "Invalid username or password")

# Create the authentication window
auth_window = tk.Tk()
auth_window.title("Authentication")

# Authentication frame
auth_frame = ttk.Frame(auth_window)
auth_frame.pack()

username_label = ttk.Label(auth_frame, text="Username:")
username_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

username_entry = ttk.Entry(auth_frame)
username_entry.grid(row=0, column=1, padx=10, pady=5)

password_label = ttk.Label(auth_frame, text="Password:")
password_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

password_entry = ttk.Entry(auth_frame, show="*")
password_entry.grid(row=1, column=1, padx=10, pady=5)

login_button = ttk.Button(auth_frame, text="Login", command=authenticate_and_start)
login_button.grid(row=2, column=0, padx=10, pady=5)

# Add a registration button and function
register_button = ttk.Button(auth_frame, text="Register", command=register_user)
register_button.grid(row=2, column=1, padx=10, pady=5)

auth_window.mainloop()

# Close the database connection when the program exits
conn.close()
