import tkinter as tk
from tkinter import filedialog, messagebox
import boto3
from botocore.exceptions import NoCredentialsError
from cryptography.fernet import Fernet

def generate_key():
    """ Generate a key and save it into a file """
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    """ Load the previously generated key """
    return open("secret.key", "rb").read()

def encrypt(filename, key):
    """ Given a filename (str) and key (bytes), it encrypts the file and write it """
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def decrypt(filename, key):
    """ Given a filename (str) and key (bytes), it decrypts the file and write it """
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    with open(filename, "wb") as file:
        file.write(decrypted_data)

def upload_to_s3(access_key, secret_key, region, bucket, file_path):
    s3 = boto3.client('s3', aws_access_key_id=access_key,
                      aws_secret_access_key=secret_key, region_name=region)
    try:
        key = load_key()
        encrypt(file_path, key)
        filename = file_path.split("/")[-1]
        s3.upload_file(file_path, bucket, filename)
        decrypt(file_path, key)  # Optionally, decrypt after upload for local use
        return "Upload Successful"
    except FileNotFoundError:
        return "The specified file was not found"
    except NoCredentialsError:
        return "Credentials not available"

def download_from_s3(access_key, secret_key, region, bucket, file_key, download_path):
    s3 = boto3.client('s3', aws_access_key_id=access_key,
                      aws_secret_access_key=secret_key, region_name=region)
    try:
        s3.download_file(bucket, file_key, download_path)
        key = load_key()
        decrypt(download_path, key)
        return "Download and decryption successful"
    except FileNotFoundError:
        return "The specified file was not found"
    except NoCredentialsError:
        return "Credentials not available"

# GUI functions
def select_file():
    file_path = filedialog.askopenfilename()
    file_path_label.config(text="Selected: " + file_path)
    return file_path

def submit_upload():
    access_key = access_key_entry.get()
    secret_key = secret_key_entry.get()
    region = region_entry.get()
    bucket = bucket_entry.get()
    file_path = file_path_label.cget("text").replace("Selected: ", "")

    result = upload_to_s3(access_key, secret_key, region, bucket, file_path)
    result_label.config(text=result)

def submit_download():
    access_key = access_key_entry.get()
    secret_key = secret_key_entry.get()
    region = region_entry.get()
    bucket = bucket_entry.get()
    file_key = file_key_entry.get()
    download_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])

    if download_path:
        result = download_from_s3(access_key, secret_key, region, bucket, file_key, download_path)
        result_label.config(text=result)
    else:
        result_label.config(text="Download cancelled")

# Initialize key
generate_key()

# GUI
root = tk.Tk()
root.title("S3 File Uploader/Downloader")

# Create and place widgets
access_key_label = tk.Label(root, text="AWS Access Key ID")
access_key_label.pack()
access_key_entry = tk.Entry(root)
access_key_entry.pack()

secret_key_label = tk.Label(root, text="AWS Secret Access Key")
secret_key_label.pack()
secret_key_entry = tk.Entry(root, show="*")
secret_key_entry.pack()

region_label = tk.Label(root, text="Region Name")
region_label.pack()
region_entry = tk.Entry(root)
region_entry.pack()

bucket_label = tk.Label(root, text="Bucket Name")
bucket_label.pack()
bucket_entry = tk.Entry(root)
bucket_entry.pack()

select_file_button = tk.Button(root, text="Select File to Upload", command=select_file)
select_file_button.pack()

file_path_label = tk.Label(root, text="No file selected")
file_path_label.pack()

upload_button = tk.Button(root, text="Upload File", command=submit_upload)
upload_button.pack()

file_key_label = tk.Label(root, text="File Key for Download")
file_key_label.pack()
file_key_entry = tk.Entry(root)
file_key_entry.pack()

download_button = tk.Button(root, text="Download and Decrypt File", command=submit_download)
download_button.pack()

result_label = tk.Label(root, text="")
result_label.pack()

root.mainloop()
