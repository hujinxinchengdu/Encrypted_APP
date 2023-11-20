# Import necessary modules
import tkinter as tk
from tkinter import filedialog, messagebox, Listbox, Scrollbar
import boto3
from cryptography.fernet import Fernet
from botocore.exceptions import NoCredentialsError


# Function to generate and save an encryption key
def generate_key():
    """ Generate a key and save it into a file """
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    return key.decode()


# Function to show generated key
def show_generated_key():
    generated_key = generate_key()
    messagebox.showinfo(
        "Generated Key", f"Your generated key is:\n{generated_key}")


# Function to load a previously generated key
def load_key():
    """ Load the previously generated key """
    return open("secret.key", "rb").read()


# Function to encrypt a file using a provided key
def encrypt(filename, key):
    """ Encrypt the file using the provided key """
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)


# Function to decrypt a file using a provided key
def decrypt(filename, key):
    """ Decrypt the file using the provided key """
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    with open(filename, "wb") as file:
        file.write(decrypted_data)


# Function to get a list of files from an S3 bucket
def get_s3_files(bucket, access_key, secret_key, region):
    s3 = boto3.client('s3', aws_access_key_id=access_key,
                      aws_secret_access_key=secret_key,
                      region_name=region)
    try:
        response = s3.list_objects_v2(Bucket=bucket)
        if 'Contents' in response:
            return [item['Key'] for item in response['Contents']]
        else:
            return []
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")
        return []


# Function to download a file from S3 and decrypt it
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


# Function to refresh the file list in the download frame
def refresh_file_list():
    bucket = aws_bucket_entry_download.get()
    access_key = aws_access_key_entry_download.get()
    secret_key = aws_secret_key_entry_download.get()
    region = aws_region_entry_download.get()

    files = get_s3_files(bucket, access_key, secret_key, region)
    file_list.delete(0, tk.END)
    for file in files:
        file_list.insert(tk.END, file)


# Function to download the selected file
def download_selected_file():
    selected_file = file_list.get(tk.ANCHOR)
    if selected_file:
        # 让用户选择文件下载到哪里
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                                 filetypes=[("All files", "*.*")])
        if save_path:
            access_key = aws_access_key_entry_download.get()
            secret_key = aws_secret_key_entry_download.get()
            region = aws_region_entry_download.get()
            bucket = aws_bucket_entry_download.get()
            user_key = user_key_entry_download.get()  # 获取用户提供的密钥

            result = download_from_s3(access_key, secret_key, region, bucket, selected_file, save_path)
            try:
                decrypt(save_path, user_key.encode())  # 使用用户密钥解密文件
                messagebox.showinfo("Result", "Download and decryption successful")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        else:
            messagebox.showerror("Error", "No save path selected")
    else:
        messagebox.showerror("Error", "No file selected or missing S3 information")


# Function to upload a file to S3
def upload_to_s3(access_key, secret_key, region, bucket, file_path):
    s3 = boto3.client('s3', aws_access_key_id=access_key,
                      aws_secret_access_key=secret_key, region_name=region)
    try:
        key = load_key()
        encrypt(file_path, key)
        filename = file_path.split("/")[-1]
        s3.upload_file(file_path, bucket, filename)
        # Optionally, decrypt after upload for local use
        decrypt(file_path, key)
        return "Upload Successful"
    except FileNotFoundError:
        return "The specified file was not found"
    except NoCredentialsError:
        return "Credentials not available"


# Function to select a file for upload
def select_file_to_upload():
    file_path = filedialog.askopenfilename()
    file_path_label.config(text="Selected: " + file_path)


# Function to submit the file upload to S3
def submit_upload_to_s3():
    file_path = file_path_label.cget("text").replace("Selected: ", "")
    if file_path and file_path != "No file selected":
        access_key = aws_access_key_entry.get()
        secret_key = aws_secret_key_entry.get()
        region = aws_region_entry.get()
        bucket = aws_bucket_entry.get()
        user_key = user_key_entry.get()  # 获取用户提供的密钥

        encrypt(file_path, user_key.encode())  # 使用用户密钥加密文件
        result = upload_to_s3(access_key, secret_key,
                              region, bucket, file_path)
        messagebox.showinfo("Result", result)
        decrypt(file_path, user_key.encode())  # 完成后解密文件（可选）
    else:
        messagebox.showerror(
            "Error", "No file selected or missing information")


# Function to switch between frames
def show_frame(frame):
    frame.tkraise()


# Create the main Tkinter window
root = tk.Tk()
root.title("S3 File Manager")

# 定义框架
window_width = 600
window_height = 400
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
center_x = int(screen_width/2 - window_width / 2)
center_y = int(screen_height/2 - window_height / 2)
root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')

# Create main, upload, and download frames
main_frame = tk.Frame(root)
upload_frame = tk.Frame(root)
download_frame = tk.Frame(root)

# Grid layout for frames
for frame in (main_frame, upload_frame, download_frame):
    frame.grid(row=0, column=0, sticky='nsew')

# 主页
main_label = tk.Label(main_frame, text="Select an Option")
main_label.pack(pady=10)
upload_button = tk.Button(main_frame, text="Upload File",
                          command=lambda: show_frame(upload_frame))
upload_button.pack()
download_button = tk.Button(main_frame, text="Download File",
                            command=lambda: show_frame(download_frame))
download_button.pack()

# 上传页面
upload_label = tk.Label(upload_frame, text="Upload Page")
upload_label.pack(pady=10)
# 上传功能的其它组件将在这里添加
# AWS Credentials
aws_access_key_label = tk.Label(upload_frame, text="AWS Access Key ID")
aws_access_key_label.pack()
aws_access_key_entry = tk.Entry(upload_frame)
aws_access_key_entry.pack()

aws_secret_key_label = tk.Label(upload_frame, text="AWS Secret Access Key")
aws_secret_key_label.pack()
aws_secret_key_entry = tk.Entry(upload_frame, show="*")
aws_secret_key_entry.pack()

aws_region_label = tk.Label(upload_frame, text="Region Name")
aws_region_label.pack()
aws_region_entry = tk.Entry(upload_frame)
aws_region_entry.pack()

aws_bucket_label = tk.Label(upload_frame, text="Bucket Name")
aws_bucket_label.pack()
aws_bucket_entry = tk.Entry(upload_frame)
aws_bucket_entry.pack()

file_path_label = tk.Label(upload_frame, text="No file selected")
file_path_label.pack()

select_file_button = tk.Button(
    upload_frame, text="Select File", command=select_file_to_upload)
select_file_button.pack()

generate_key_button = tk.Button(
    upload_frame, text="Generate Encryption Key", command=show_generated_key)
generate_key_button.pack()


user_key_label = tk.Label(upload_frame, text="Encryption Key")
user_key_label.pack()
user_key_entry = tk.Entry(upload_frame, show="*")
user_key_entry.pack()

upload_button = tk.Button(
    upload_frame, text="Upload File", command=submit_upload_to_s3)
upload_button.pack()


back_button_upload = tk.Button(upload_frame, text="Back to Main Menu",
                               command=lambda: show_frame(main_frame))
back_button_upload.pack()


# 下载页面
download_label = tk.Label(download_frame, text="Download Page")
download_label.pack(pady=10)
# 下载功能的其它组件将在这里添加

aws_access_key_label_download = tk.Label(
    download_frame, text="AWS Access Key ID")
aws_access_key_label_download.pack()
aws_access_key_entry_download = tk.Entry(download_frame)
aws_access_key_entry_download.pack()

aws_secret_key_label_download = tk.Label(
    download_frame, text="AWS Secret Access Key")
aws_secret_key_label_download.pack()
aws_secret_key_entry_download = tk.Entry(download_frame, show="*")
aws_secret_key_entry_download.pack()

aws_region_label_download = tk.Label(download_frame, text="Region Name")
aws_region_label_download.pack()
aws_region_entry_download = tk.Entry(download_frame)
aws_region_entry_download.pack()

aws_bucket_label_download = tk.Label(download_frame, text="Bucket Name")
aws_bucket_label_download.pack()
aws_bucket_entry_download = tk.Entry(download_frame)
aws_bucket_entry_download.pack()

file_list = Listbox(download_frame)
file_list.pack(fill=tk.BOTH, expand=True)

refresh_button = tk.Button(
    download_frame, text="Refresh File List", command=refresh_file_list)
refresh_button.pack()

user_key_label_download = tk.Label(download_frame, text="Decryption Key")
user_key_label_download.pack()
user_key_entry_download = tk.Entry(download_frame, show="*")
user_key_entry_download.pack()

# 添加下载按钮
download_button = tk.Button(download_frame, text="Download Selected File", command=download_selected_file)
download_button.pack()

back_button_download = tk.Button(download_frame, text="Back to Main Menu",
                                 command=lambda: show_frame(main_frame))
back_button_download.pack()

show_frame(main_frame)
root.mainloop()
