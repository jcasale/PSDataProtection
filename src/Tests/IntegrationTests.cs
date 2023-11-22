namespace Tests;

using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security;
using System.Security.Cryptography;
using PSDataProtection;
using Xunit;

public sealed class IntegrationTests : IDisposable
{
    private readonly Runspace runSpace;
    private readonly PowerShell powerShell;

    public IntegrationTests()
    {
        var initialSessionState = InitialSessionState.Create();

        var entry1 = new SessionStateCmdletEntry("New-DataProtectionSecret", typeof(NewDataProtectionSecretCommand), null);
        initialSessionState.Commands.Add(entry1);

        var entry2 = new SessionStateCmdletEntry("Read-DataProtectionSecret", typeof(ReadDataProtectionSecretCommand), null);
        initialSessionState.Commands.Add(entry2);

        this.runSpace = RunspaceFactory.CreateRunspace(initialSessionState);
        this.powerShell = PowerShell.Create();

        this.runSpace.Open();
        this.powerShell.Runspace = this.runSpace;
    }

    public static IEnumerable<object[]> NewDataProtectionSecretArguments()
    {
        yield return new object[] { Guid.NewGuid().ToString(), DataProtectionScope.CurrentUser };
        yield return new object[] { Guid.NewGuid().ToString(), DataProtectionScope.LocalMachine };
    }

    [Theory]
    [MemberData(nameof(NewDataProtectionSecretArguments))]
    public void ArgumentsAsObjectInPipelineShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        this.powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope);

        var psObject = new PSObject();
        psObject.Members.Add(new PSNoteProperty(nameof(NewDataProtectionSecretCommand.SecureString), secureString));
        psObject.Members.Add(new PSNoteProperty(nameof(NewDataProtectionSecretCommand.Scope), scope));

        var results = this.powerShell.Invoke<string>(new[] { psObject });

        Assert.Single(results);

        Assert.Equal(data, results[0]);
    }

    [Theory]
    [MemberData(nameof(NewDataProtectionSecretArguments))]
    public void ArgumentsAsParametersShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        this.powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), secureString)
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), scope)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope);

        var results = this.powerShell.Invoke<string>();

        Assert.Single(results);

        Assert.Equal(data, results[0]);
    }

    [Theory]
    [MemberData(nameof(NewDataProtectionSecretArguments))]
    public void ResultAsSecureStringShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        this.powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), secureString)
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), scope)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope)
            .AddParameter(nameof(ReadDataProtectionSecretCommand.AsSecureString), true);

        var results = this.powerShell.Invoke<SecureString>();

        Assert.Single(results);

        Assert.Equal(data, results[0].ToPlainString());
    }

    [Theory]
    [MemberData(nameof(NewDataProtectionSecretArguments))]
    public void ScopeInPipelineShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        this.powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), secureString)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope);

        var results = this.powerShell.Invoke<string>(new[] { scope });

        Assert.Single(results);

        Assert.Equal(data, results[0]);
    }

    [Theory]
    [MemberData(nameof(NewDataProtectionSecretArguments))]
    public void SecureStringInPipelineShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        this.powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), scope)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope);

        var results = this.powerShell.Invoke<string>(new[] { secureString });

        Assert.Single(results);

        Assert.Equal(data, results[0]);
    }

    [Theory]
    [MemberData(nameof(NewDataProtectionSecretArguments))]
    public void ScopeAsObjectInPipelineShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        this.powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), secureString)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope);

        var psObject = new PSObject();
        psObject.Members.Add(new PSNoteProperty(nameof(NewDataProtectionSecretCommand.Scope), scope));

        var results = this.powerShell.Invoke<string>(new[] { psObject });

        Assert.Single(results);

        Assert.Equal(data, results[0]);
    }

    [Theory]
    [MemberData(nameof(NewDataProtectionSecretArguments))]
    public void SecureStringAsObjectInPipelineShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        this.powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), scope)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope);

        var psObject = new PSObject();
        psObject.Members.Add(new PSNoteProperty(nameof(NewDataProtectionSecretCommand.SecureString), secureString));

        var results = this.powerShell.Invoke<string>(new[] { psObject });

        Assert.Single(results);

        Assert.Equal(data, results[0]);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        this.powerShell.Dispose();
        this.runSpace.Dispose();
    }
}