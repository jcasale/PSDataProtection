namespace Tests;

using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.Cryptography;
using PSDataProtection;
using Xunit;

public sealed class ParameterTests : IDisposable
{
    private readonly Runspace runSpace;
    private readonly PowerShell powerShell;

    public ParameterTests()
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

    [Fact]
    public void NewDataProtectionSecretWithEmptySecureStringShouldThrow()
    {
        this.powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), string.Empty.ToSecureString())
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), DataProtectionScope.CurrentUser);

        var exception = Record.Exception(this.powerShell.Invoke);

        Assert.IsType<CmdletInvocationException>(exception);
        Assert.IsType<InvalidOperationException>(exception.InnerException);
    }

    [Fact]
    public void NewDataProtectionSecretWithInvalidScopeShouldThrow()
    {
        this.powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), Guid.NewGuid().ToString().ToSecureString())
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), Guid.NewGuid().ToString());

        var exception = Record.Exception(this.powerShell.Invoke);

        Assert.IsType<ParameterBindingException>(exception);
        Assert.IsType<PSInvalidCastException>(exception.InnerException);
    }

    [Fact]
    public void NewDataProtectionSecretWithInvalidSecureStringShouldThrow()
    {
        this.powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), Guid.NewGuid().ToString())
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), DataProtectionScope.CurrentUser);

        var exception = Record.Exception(this.powerShell.Invoke);

        Assert.IsType<ParameterBindingException>(exception);
        Assert.IsType<PSInvalidCastException>(exception.InnerException);
    }

    [Fact]
    public void ReadDataProtectionSecretWithEmptyProtectedStringShouldThrow()
    {
        this.powerShell
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Protected), string.Empty)
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), DataProtectionScope.CurrentUser);

        var exception = Record.Exception(this.powerShell.Invoke);

        Assert.IsAssignableFrom<ParameterBindingException>(exception);
        Assert.IsType<ValidationMetadataException>(exception.InnerException);
    }

    [Fact]
    public void ReadDataProtectionSecretWithInvalidProtectedStringShouldThrow()
    {
        this.powerShell
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Protected), Guid.NewGuid())
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), DataProtectionScope.CurrentUser);

        var exception = Record.Exception(this.powerShell.Invoke);

        Assert.IsType<CmdletInvocationException>(exception);
        Assert.IsType<FormatException>(exception.InnerException);
    }

    [Fact]
    public void ReadDataProtectionSecretWithInvalidScopeShouldThrow()
    {
        this.powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), Guid.NewGuid().ToString())
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), DataProtectionScope.CurrentUser)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), Guid.NewGuid().ToString());

        var exception = Record.Exception(this.powerShell.Invoke);

        Assert.IsType<ParameterBindingException>(exception);
        Assert.IsType<PSInvalidCastException>(exception.InnerException);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        this.powerShell.Dispose();
        this.runSpace.Dispose();
    }
}