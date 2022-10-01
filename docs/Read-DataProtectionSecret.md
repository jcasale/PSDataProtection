---
external help file: PSDataProtection.dll-Help.xml
Module Name: PSDataProtection
online version:
schema: 2.0.0
---

# Read-DataProtectionSecret

## SYNOPSIS

Reads the unencrypted value of a secret that was encrypted with data protection.

## DESCRIPTION

The Read-DataProtectionSecret cmdlet decrypts a secret that was previously encrypted with data protection.

## EXAMPLES

### ----------- Example 1: Unprotect a secret -----------

```powershell
PS> $protected |Read-DataProtectionSecret -Scope CurrentUser
Hello World!
```

This command unprotects a secret that was protected using CurrentUser scope and returns a string.

### ----------- Example 2: Unprotect a secret -----------

```powershell
PS> $secureString = $protected |Read-DataProtectionSecret -Scope CurrentUser -AsSecureString
```

This command unprotects a secret that was protected using CurrentUser scope and returns a SecureString.

### ----------- Example 3: Unprotect a secret stored on disk -----------

Ensure PowerShell is running in the context of the account that protected the data.

```powershell
PS> Get-Content .\secret.json
{
  "Protected": "AQAAANCMnd8BFdERjHoAwE ... 2pQQ==",
  "Scope": "CurrentUser"
}
PS> Get-Content .\secret.json |ConvertFrom-Json |Read-DataProtectionSecret
Hello World!
```

This command unprotects a secret that was previously stored on disk for use within automation.