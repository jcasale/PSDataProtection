---
external help file: PSDataProtection.dll-Help.xml
Module Name: PSDataProtection
online version:
schema: 2.0.0
---

# New-DataProtectionSecret

## SYNOPSIS

Creates an encrypted version of a secret using data protection.

## DESCRIPTION

The New-DataProtectionSecret cmdlet creates an encrypted version of a secret using data protection.

## EXAMPLES

### ----------- Example 1: Protect a secret using CurrentUser scope -----------

```powershell
PS> $protected = New-DataProtectionSecret -Scope CurrentUser

cmdlet New-DataProtectionSecret at command pipeline position 1
Supply values for the following parameters:
(Type !? for Help.)
SecureString: ************
```

This command protects a secret using CurrentUser scope and prompt for the value securely.

### ----------- Example 2: Store a protected secret on disk -----------

Ensure PowerShell is running in the context of the account that will be used to unprotect the secret.

```powershell
PS> $protected = New-DataProtectionSecret -Scope CurrentUser

cmdlet New-DataProtectionSecret at command pipeline position 1
Supply values for the following parameters:
(Type !? for Help.)
SecureString: ************

PS> [pscustomobject]@{ Protected = $protected; Scope = 'CurrentUser' } |
    ConvertTo-Json |
    Set-Content -Path secret.json -Encoding UTF8
```

This command stores a protected secret on disk for use by the same account within automation.