Param(
    [CmdletBinding()]
    [Parameter(Mandatory = $True)]
    [ValidateSet("add", "remove", "import", "list")]
    $Action,
    
    [Parameter()]
    $Name
)

$ErrorActionPreference = "Stop"

function Encrypt
{
    Param([SecureString]$Passphrase, [String]$Data)

    try {
        $DataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
        $PassphraseBytes = [System.Text.Encoding]::UTF8.GetBytes((Convert-SecureString $Passphrase))
        $SaltBytes = New-Object Byte[] @(8)
        
        $Sha256 = [Security.Cryptography.HashAlgorithm]::Create("SHA256")
        $HashBytes = $Sha256.ComputeHash($DataBytes);
            
        $Rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $Rng.GetBytes($SaltBytes)
        
        $Pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes @($PassphraseBytes, $SaltBytes, 409600)
        $KeyBytes = $Pbkdf2.GetBytes(16)
        
        $Aes = New-Object "System.Security.Cryptography.AesManaged"
        $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $Aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $Aes.BlockSize = 128
        $Aes.KeySize = 256
        $Aes.Key = $KeyBytes
        
        $Encryptor = $Aes.CreateEncryptor()
        $DataSecret = $Encryptor.TransformFinalBlock($DataBytes, 0, $DataBytes.Length)
        $DataSecretWithHashAndIVAndSalt = $HashBytes + $Pbkdf2.Salt + $Aes.IV + $DataSecret
        
        $Rng.Dispose()
        $Sha256.Dispose()
        $Aes.Dispose()
        $Pbkdf2.Dispose()
        
        [System.Convert]::ToBase64String($DataSecretWithHashAndIVAndSalt)
    }
    catch
    {
        Write-Error $Error[0]
    }
}

function Decrypt
{
    Param([SecureString]$Passphrase, [string]$DataSecretWithHashAndIVAndSaltBase64)

    try {
        $DataSecretWithHashAndIVAndSalt = [System.Convert]::FromBase64String($DataSecretWithHashAndIVAndSaltBase64)
        
        $PassphraseBytes = [System.Text.Encoding]::UTF8.GetBytes((Convert-SecureString $Passphrase))
        $HashBytes = $DataSecretWithHashAndIVAndSalt[0..31]
        $SaltBytes = $DataSecretWithHashAndIVAndSalt[32..39]
        $IVBytes = $DataSecretWithHashAndIVAndSalt[40..55]
       
        $Pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes @($PassphraseBytes, $SaltBytes, 409600)
        $KeyBytes = $Pbkdf2.GetBytes(16)
        
        $Aes = New-Object "System.Security.Cryptography.AesManaged"
        $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $Aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $Aes.BlockSize = 128
        $Aes.KeySize = 256
        $Aes.Key = $KeyBytes
        $Aes.IV = $IVBytes

        $Decryptor = $Aes.CreateDecryptor();
        $DataBase64 = $Decryptor.TransformFinalBlock($DataSecretWithHashAndIVAndSalt, 56, $DataSecretWithHashAndIVAndSalt.Length - 56);
        $Data = [System.Text.Encoding]::UTF8.GetString($DataBase64).Trim([char]0)
        $DataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
        
        $Sha256 = [Security.Cryptography.HashAlgorithm]::Create("SHA256")
        $CheckHashBytes = $Sha256.ComputeHash($DataBytes);
        
        if ((Compare-Object $HashBytes $CheckHashBytes).Length -gt 0)
        {
            throw "Invalid passphrase was entered."
        }        
       
        $Sha256.Dispose()
        $Aes.Dispose()
        $Pbkdf2.Dispose()
        
        $Data
    }
    catch
    {
        Write-Error $Error[0]
    }
}

function Get-ProfileDataString
{
    Param([string]$Name, [string]$Region, [string]$AccessKeyId, [SecureString]$SecretAccessKey)
    
    "AWS_PROFILE_NAME=$Name`nAWS_DEFAULT_REGION=$Region`nAWS_ACCESS_KEY_ID=$AccessKeyId`nAWS_SECRET_ACCESS_KEY=$(Convert-SecureString $SecretAccessKey)`n"
}

function Convert-SecureString
{
    Param([SecureString]$Value)
    [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value))
}

$HomeDirectory = "$($Env:SystemDrive)$($Env:HomePath)"
$CredentialsDirectory = "$HomeDirectory\.aws"

$ProfilesPaths = Get-ChildItem $CredentialsDirectory *.awscreds
$Profiles = @{}
foreach ($Path in $ProfilesPaths)
{
    $Profiles.Add($Path.BaseName, "$CredentialsDirectory\.aws\$($Path.Name)")
}

Write-Host ""

switch ($Action)
{
    "list"
    {
        if ($Profiles.Count -gt 0)
        {
            Write-Host "Available AWS credential profiles:"
            foreach ($Profile in $Profiles.getEnumerator())
            {
                Write-Host "`t- $($Profile.Name)"
            }
        }
        else
        {
            Write-Host "No AWS credential profiles were found."
        }
        
        break;
    }
    
    "add"
    {
        if ($Name -eq $Null)
        {
            throw "Profile name not specified."
        }
        if ($Profiles.ContainsKey($Name))
        {
            throw "Profile already exists."
        }
    
        $Path = "$CredentialsDirectory\$($Name).awscreds"
        
        $AwsRegion = Read-Host "Enter the AWS region"
        $AwsAccessKeyId = Read-Host "Enter the AWS access key id"
        $AwsSecretAccessKey = Read-Host -AsSecureString "Enter the AWS secret access key"
        $Passphrase = Read-Host -AsSecureString "Enter a passphrase"
        
        $EncryptedProfileData = Encrypt $Passphrase (Get-ProfileDataString $Name $AwsRegion $AwsAccessKeyId $AwsSecretAccessKey)        
        if ($EncryptedProfileData -eq $Null)
        {
            throw "Encryption failed."
        }
        
        [System.IO.File]::WriteAllLines($Path, $EncryptedProfileData)
        
        Write-Host "Profile added."
    }
    
    "import"
    {
        if ($Name -eq $Null)
        {
            throw "Profile name not specified."
        }
        if (-Not $Profiles.ContainsKey($Name))
        {
            throw "Profile does not exist."
        }
        
        $Path = "$CredentialsDirectory\$($Name).awscreds"
        $Passphrase = Read-Host -AsSecureString "Enter the passphrase"
        
        $ProfileData = Decrypt $Passphrase (Get-Content $Path)
        if ($ProfileData -eq $Null)
        {
            throw "Decryption failed."
        }
        
        $ProfileLines = $ProfileData.Split("`n")
        foreach ($ProfileLine in $ProfileLines)
        {
            if ([string]::IsNullOrWhiteSpace($ProfileLine))
            {
                continue
            }
            
            $LineParts = $ProfileLine.Split("=")
            $Name = $LineParts[0]
            $Value = $LineParts[1]
            
            [Environment]::SetEnvironmentVariable($Name, $Value, "Process");
        }
        
        $CallerIdentityJson = [string]::Join("", (Invoke-Expression "aws sts get-caller-identity"))
        $CallerIdentity = ConvertFrom-Json $CallerIdentityJson;
        $CallerParts = $CallerIdentity.Arn.Split(":")
        
        Write-Host "Imported profile. Account is $($CallerParts[4]). User is $($CallerParts[5])."
    }
    
    "remove"
    {
        if ($Name -eq $Null)
        {
            throw "Profile name not specified."
        }
        if (-Not $Profiles.ContainsKey($Name))
        {
            throw "Profile does not exist."
        }
        
        $Path = "$CredentialsDirectory\$($Name).awscreds"

        $Confirm = Read-Host "Confirm removal (only ""yes"" will be accepted)"
        if ($Confirm -eq "yes")
        {
            Remove-Item $Path
            Write-Host "Profile $Name was removed."
        }
        else
        {
            Write-Host "Aborting, no profile was removed."
        }
    }
}

Write-Host