# Invoke-WebExfiltration
PowerShell function to exfiltrate data via HTTP(s) POST request (with file gzip compression and AES-256 encryption)

Exfiltrate files to a remote server in a secure, encrypted way


## Description

## Features



## Technical details / design thoughts

- File encryption
  - File names and file content is encrypted with AES-256
  - Key size: 256 bit, block size: 128 bit, IV: 128 bit, PKCS7 padding
  - The password is SHA256 hashed to receive a 256 bit long key
  - This means that it is even safe to transfer files via plain text HTTP (assuming you use a strong password)

- Gzip compression
  - After encryption the binary data is compressed via Gzip.
  - It's quick for not too large files and reduces the size by a good few percent

- No password protection for file upload
  - The server will only accept data from POST requests which it can successfully decrypt. 
  - It tests that first on the file name.
  - If the content can't be decrypted the file name the file binary will be ignored and is discarded.
  - I kind of see that as a password protection 'light' for the file upload to prevent unwanted uploads from 3rd parties.

- Loot folder structure
  - The tool keeps the identical folder structure as it exists on the client


## Examples