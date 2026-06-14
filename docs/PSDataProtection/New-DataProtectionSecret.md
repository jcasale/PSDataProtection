---
document type: cmdlet
external help file: PSDataProtection.dll-Help.xml
HelpUri: ''
Locale: en-US
Module Name: PSDataProtection
ms.date: 06-14-2026
PlatyPS schema version: 2024-05-01
title: New-DataProtectionSecret
---

# New-DataProtectionSecret

## SYNOPSIS

Creates an encrypted version of a secret using data protection.

## SYNTAX

### __AllParameterSets

```
New-DataProtectionSecret [-SecureString] <securestring> [-Scope] <DataProtectionScope>
 [<CommonParameters>]
```

## ALIASES

None

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

## PARAMETERS

### -Scope

Specifies the scope of the data protection to be applied.

```yaml
Type: System.Nullable`1[System.Security.Cryptography.DataProtectionScope]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 1
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: true
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -SecureString

Specifies the data to encrypt and encode to a base64 string.

```yaml
Type: System.Security.SecureString
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 0
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: true
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.Security.SecureString

You can pipe the data to encrypt and encode to a base64 string.

### System.Security.Cryptography.DataProtectionScope

You can pipe the scope of the data protection to be applied.

## OUTPUTS

### System.String

Returns the protected version of the data.

## NOTES

## RELATED LINKS
