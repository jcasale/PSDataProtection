# PowerShell Data Protection Module

The `PSDataProtection` module utilizes Microsoft Data Protection to encrypt and decrypt secrets.

## Installation

The module is distributed as a Windows Installer package (the PowerShell Gallery is not suitable for some enterprises).

Run the installer manually or in unattended mode:

```bat
msiexec.exe /i ps-data-protection.msi /qn
```

The default installation path is:

```bat
%ProgramFiles%\WindowsPowerShell\Modules\PSDataProtection
```

## Documentation

Use `Get-Command` and `Get-Help` to enumerate the cmdlets with this module and obtain their documentation:

```powershell
Get-Command -Module PSDataProtection
Get-Help New-DataProtectionSecret -Full
```

## Useful Links

- [How to: Use Data Protection](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)
- [ProtectedData Class](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata)
- [DataProtectionScope Enum](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.dataprotectionscope)