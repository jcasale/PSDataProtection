[CmdletBinding()]
param
(
    [Parameter(Position=0)]
    [string]
    $Path = (Join-Path $PSScriptRoot 'PSDataProtection.psd1'),
    [Parameter(Position=1)]
    [Version]
    $Version
)

Set-StrictMode -Version Latest

if (Test-Path $Path)
{
    Remove-Item $Path -Force
}

if ($null -eq $Version)
{
    try
    {
        $result = & git.exe describe --tags --abbrev=0
    }
    catch
    {
        throw
    }

    if ($LASTEXITCODE -ne 0)
    {
        throw
    }

    $softwareVersion = $result.Split('-')[0].TrimStart('v')

    Write-Verbose ('Using git version {0}.' -f $softwareVersion)
}
else
{
    $softwareVersion = $Version.ToString()

    Write-Verbose ('Using specified version {0}.' -f $softwareVersion)
}

$content = @'
@{{
  RootModule = 'PSDataProtection.dll'
  ModuleVersion = '{0}'
  GUID = 'fb9ace89-dcc1-4f47-99b3-708753440db3'
  Author = 'Joseph L. Casale'
  CompanyName = 'Joseph L. Casale'
  Copyright = '(c) Joseph L. Casale. All rights reserved.'
  Description = 'A PowerShell module that utilizes Microsoft Data Protection to encrypt and decrypt secrets.'
  RequiredAssemblies = @()
  NestedModules = @()
  FunctionsToExport = @()
  CmdletsToExport = @('New-DataProtectionSecret', 'Read-DataProtectionSecret')
  VariablesToExport = @()
  AliasesToExport = @()
  PrivateData = @{{ PSData = @{{}} }}
}}
'@ -f $softwareVersion

Set-Content -Value $content -Path $Path