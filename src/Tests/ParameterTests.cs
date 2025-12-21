namespace Tests;

using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.Cryptography;

using PSDataProtection;

[TestClass]
public class ParameterTests
{
    [TestMethod]
    public void NewDataProtectionSecretWithEmptySecureStringShouldThrow()
    {
        using var secureString = string.Empty.ToSecureString();

        using var powerShell = CreateInstance();
        powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), secureString)
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), DataProtectionScope.CurrentUser);

        var exception = Assert.Throws<Exception>(powerShell.Invoke);

        Assert.IsInstanceOfType<CmdletInvocationException>(exception);
        Assert.IsInstanceOfType<InvalidOperationException>(exception.InnerException);
    }

    [TestMethod]
    public void NewDataProtectionSecretWithInvalidScopeShouldThrow()
    {
        using var secureString = Guid.NewGuid().ToString().ToSecureString();

        using var powerShell = CreateInstance();
        powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), secureString)
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), Guid.NewGuid().ToString());

        var exception = Assert.Throws<Exception>(powerShell.Invoke);

        Assert.IsInstanceOfType<ParameterBindingException>(exception);
        Assert.IsInstanceOfType<PSInvalidCastException>(exception.InnerException);
    }

    [TestMethod]
    public void NewDataProtectionSecretWithInvalidSecureStringShouldThrow()
    {
        using var powerShell = CreateInstance();
        powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), Guid.NewGuid().ToString())
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), DataProtectionScope.CurrentUser);

        var exception = Assert.Throws<Exception>(powerShell.Invoke);

        Assert.IsInstanceOfType<ParameterBindingException>(exception);
        Assert.IsInstanceOfType<PSInvalidCastException>(exception.InnerException);
    }

    [TestMethod]
    public void ReadDataProtectionSecretWithEmptyProtectedStringShouldThrow()
    {
        using var powerShell = CreateInstance();
        powerShell
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Protected), string.Empty)
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), DataProtectionScope.CurrentUser);

        var exception = Assert.Throws<Exception>(powerShell.Invoke);

        Assert.IsInstanceOfType<ParameterBindingException>(exception);
        Assert.IsInstanceOfType<ValidationMetadataException>(exception.InnerException);
    }

    [TestMethod]
    public void ReadDataProtectionSecretWithInvalidProtectedStringShouldThrow()
    {
        using var powerShell = CreateInstance();
        powerShell
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Protected), Guid.NewGuid())
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), DataProtectionScope.CurrentUser);

        var exception = Assert.Throws<Exception>(powerShell.Invoke);

        Assert.IsInstanceOfType<CmdletInvocationException>(exception);
        Assert.IsInstanceOfType<FormatException>(exception.InnerException);
    }

    [TestMethod]
    public void ReadDataProtectionSecretWithInvalidScopeShouldThrow()
    {
        using var powerShell = CreateInstance();
        powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), Guid.NewGuid().ToString())
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), DataProtectionScope.CurrentUser)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), Guid.NewGuid().ToString());

        var exception = Assert.Throws<Exception>(powerShell.Invoke);

        Assert.IsInstanceOfType<ParameterBindingException>(exception);
        Assert.IsInstanceOfType<PSInvalidCastException>(exception.InnerException);
    }

    private static PowerShell CreateInstance()
    {
        var initialSessionState = InitialSessionState.CreateDefault2();

        var entry1 = new SessionStateCmdletEntry("New-DataProtectionSecret", typeof(NewDataProtectionSecretCommand), null);
        initialSessionState.Commands.Add(entry1);

        var entry2 = new SessionStateCmdletEntry("Read-DataProtectionSecret", typeof(ReadDataProtectionSecretCommand), null);
        initialSessionState.Commands.Add(entry2);

        return PowerShell.Create(initialSessionState);
    }
}