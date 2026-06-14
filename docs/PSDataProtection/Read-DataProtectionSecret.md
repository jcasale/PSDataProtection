---
document type: cmdlet
external help file: PSDataProtection.dll-Help.xml
HelpUri: ''
Locale: en-US
Module Name: PSDataProtection
ms.date: 06-14-2026
PlatyPS schema version: 2024-05-01
title: Read-DataProtectionSecret
---

# Read-DataProtectionSecret

## SYNOPSIS

Reads the unencrypted value of a secret that was encrypted with data protection.

## SYNTAX

### StringOutput (Default)

```
Read-DataProtectionSecret [-Protected] <string> [-Scope] <DataProtectionScope> [<CommonParameters>]
```

### SecureStringOutput

```
Read-DataProtectionSecret [-Protected] <string> [-Scope] <DataProtectionScope> [-AsSecureString]
 [<CommonParameters>]
```

## ALIASES

None

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

## PARAMETERS

### -AsSecureString

Specifies the output should be a secure string instead of a string.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: SecureStringOutput
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Protected

Specifies the base64 encoded data to decrypt.

```yaml
Type: System.String
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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String

You can pipe the protected base64 string to unprotect.

### System.Security.Cryptography.DataProtectionScope

You can pipe the scope of the data protection to be applied.

## OUTPUTS

### System.String

Returns the unprotected version of the data.

### System.Security.SecureString

Returns the unprotected version of the data.

## NOTES

## RELATED LINKS
