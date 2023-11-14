
import tkinter as tk
from tkinter import filedialog
import boto3
from botocore.exceptions import NoCredentialsError

def upload_to_s3(access_key, secret_key, region, bucket, file_path):
    s3 = boto3.client('s3', aws_access_key_id=access_key,
                      aws_secret_access_key=secret_key, region_name=region)
    try:
        filename = file_path.split("/")[-1]
        s3.upload_file(file_path, bucket, filename)
        return "Upload Successful"
    except FileNotFoundError:
        return "The specified file was not found"
    except NoCredentialsError:
        return "Credentials not available"

def select_file():
    file_path = filedialog.askopenfilename()
    file_path_label.config(text="Selected: " + file_path)
    return file_path

def submit_action():
    access_key = access_key_entry.get()
    secret_key = secret_key_entry.get()
    region = region_entry.get()
    bucket = bucket_entry.get()
    file_path = file_path_label.cget("text").replace("Selected: ", "")

    result = upload_to_s3(access_key, secret_key, region, bucket, file_path)
    result_label.config(text=result)

root = tk.Tk()
root.title("S3 File Uploader")

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

select_file_button = tk.Button(root, text="Select File", command=select_file)
select_file_button.pack()

file_path_label = tk.Label(root, text="No file selected")
file_path_label.pack()

submit_button = tk.Button(root, text="Upload File", command=submit_action)
submit_button.pack()

result_label = tk.Label(root, text="")
result_label.pack()

root.mainloop()
