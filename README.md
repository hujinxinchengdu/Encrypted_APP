# S3 File Encryption and Decryption Tool

This tool provides a simple graphical user interface (GUI) to upload encrypted files to AWS S3 and download and decrypt files from S3. It allows users to generate encryption keys or enter their own keys for encrypting and decrypting files.

## Features

- Upload files to AWS S3 with encryption.
- Download and decrypt files from AWS S3.
- Generate encryption keys.
- Use custom encryption keys for added security.
- View files stored in AWS S3 buckets.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Python 3.x installed on your machine.
- AWS account and credentials (Access Key ID and Secret Access Key).
- An S3 bucket created in your AWS account.

## Installation

To install the required libraries, run the following command:

```bash
pip install boto3 cryptography tkinter
```

## Usage
Follow these steps to use the tool:

### Starting the Application:
Run the script to start the application. The GUI window will open.
### Uploading Files:

Navigate to the upload tab.
Enter your AWS credentials and the name of your S3 bucket.
Either generate a new encryption key or enter your own.
Select the file you wish to upload and encrypt.
Click on the 'Upload File' button.

### Downloading Files:
Navigate to the download tab.
Enter your AWS credentials and the name of your S3 bucket.
Enter the decryption key (the same key used for encrypting the file).
Select a file from the list of files in your S3 bucket.
Click on the 'Download Selected File' button to download and decrypt the file.
### Security Considerations
Always keep your AWS credentials secure.
Do not share your encryption keys publicly.
Be careful with the generated keys; losing the key means losing access to the data encrypted with that key.
This tool is intended for basic use cases and might not be suitable for highly sensitive data.

### License
This project is licensed under the MIT License.

### Contributions
Contributions to this project are welcome. Please ensure you follow the existing code style and add or update tests as necessary.
