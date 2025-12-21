namespace Tests;

using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security;
using System.Security.Cryptography;

using PSDataProtection;

[TestClass]
public class IntegrationTests
{
    public static IEnumerable<(string Data, DataProtectionScope Scope)> NewDataProtectionSecretArguments() =>
    [
        new(Guid.NewGuid().ToString(), DataProtectionScope.CurrentUser),
        new(Guid.NewGuid().ToString(), DataProtectionScope.LocalMachine)
    ];

    [TestMethod]
    [DynamicData(nameof(NewDataProtectionSecretArguments))]
    public void ArgumentsAsObjectInPipelineShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        using var powerShell = CreateInstance();
        powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope);

        var psObject = new PSObject();
        psObject.Members.Add(new PSNoteProperty(nameof(NewDataProtectionSecretCommand.SecureString), secureString));
        psObject.Members.Add(new PSNoteProperty(nameof(NewDataProtectionSecretCommand.Scope), scope));

        var results = powerShell.Invoke<string>(new[] { psObject });

        Assert.ContainsSingle(results);

        Assert.AreEqual(data, results[0]);
    }

    [TestMethod]
    [DynamicData(nameof(NewDataProtectionSecretArguments))]
    public void ArgumentsAsParametersShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        using var powerShell = CreateInstance();
        powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), secureString)
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), scope)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope);

        var results = powerShell.Invoke<string>();

        Assert.ContainsSingle(results);

        Assert.AreEqual(data, results[0]);
    }

    [TestMethod]
    [DynamicData(nameof(NewDataProtectionSecretArguments))]
    public void ResultAsSecureStringShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        using var powerShell = CreateInstance();
        powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), secureString)
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), scope)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope)
            .AddParameter(nameof(ReadDataProtectionSecretCommand.AsSecureString), true);

        var results = powerShell.Invoke<SecureString>();

        Assert.ContainsSingle(results);

        Assert.AreEqual(data, results[0].ToPlainString());
    }

    [TestMethod]
    [DynamicData(nameof(NewDataProtectionSecretArguments))]
    public void ScopeInPipelineShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        using var powerShell = CreateInstance();
        powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), secureString)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope);

        var results = powerShell.Invoke<string>(new[] { scope });

        Assert.ContainsSingle(results);

        Assert.AreEqual(data, results[0]);
    }

    [TestMethod]
    [DynamicData(nameof(NewDataProtectionSecretArguments))]
    public void SecureStringInPipelineShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        using var powerShell = CreateInstance();
        powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), scope)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope);

        var results = powerShell.Invoke<string>(new[] { secureString });

        Assert.ContainsSingle(results);

        Assert.AreEqual(data, results[0]);
    }

    [TestMethod]
    [DynamicData(nameof(NewDataProtectionSecretArguments))]
    public void ScopeAsObjectInPipelineShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        using var powerShell = CreateInstance();
        powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.SecureString), secureString)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope);

        var psObject = new PSObject();
        psObject.Members.Add(new PSNoteProperty(nameof(NewDataProtectionSecretCommand.Scope), scope));

        var results = powerShell.Invoke<string>(new[] { psObject });

        Assert.ContainsSingle(results);

        Assert.AreEqual(data, results[0]);
    }

    [TestMethod]
    [DynamicData(nameof(NewDataProtectionSecretArguments))]
    public void SecureStringAsObjectInPipelineShouldPass(string data, DataProtectionScope scope)
    {
        using var secureString = data.ToSecureString();

        using var powerShell = CreateInstance();
        powerShell
            .AddCommand("New-DataProtectionSecret")
            .AddParameter(nameof(NewDataProtectionSecretCommand.Scope), scope)
            .AddCommand("Read-DataProtectionSecret")
            .AddParameter(nameof(ReadDataProtectionSecretCommand.Scope), scope);

        var psObject = new PSObject();
        psObject.Members.Add(new PSNoteProperty(nameof(NewDataProtectionSecretCommand.SecureString), secureString));

        var results = powerShell.Invoke<string>(new[] { psObject });

        Assert.ContainsSingle(results);

        Assert.AreEqual(data, results[0]);
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