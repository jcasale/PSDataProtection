namespace PSDataProtection;

using System;
using System.Management.Automation;
using System.Security;
using System.Security.Cryptography;

[Cmdlet(VerbsCommunications.Read, "DataProtectionSecret", DefaultParameterSetName = StringParameterSetName)]
[OutputType(typeof(string), ParameterSetName = [StringParameterSetName])]
[OutputType(typeof(SecureString), ParameterSetName = [SecureStringParameterSetName])]
public class ReadDataProtectionSecretCommand : PSCmdlet
{
    public const string StringParameterSetName = "StringOutput";
    public const string SecureStringParameterSetName = "SecureStringOutput";

    private readonly System.Text.UTF8Encoding encoding = new();

    [Parameter(
        Position = 0,
        Mandatory = true,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        HelpMessage = "Specifies the base64 encoded data to decrypt.")]
    [ValidateNotNullOrEmpty]
    public string Protected { get; set; }

    [Parameter(
        Position = 1,
        Mandatory = true,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        HelpMessage = "Specifies the scope of the data protection to be applied.")]
    public DataProtectionScope? Scope { get; set; }

    [Parameter(
        ParameterSetName = SecureStringParameterSetName,
        HelpMessage = "Specifies the output should be a secure string instead of a string.")]
    public SwitchParameter AsSecureString { get; set; }

    /// <inheritdoc />
    protected override void ProcessRecord()
    {
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(this.Protected);
        }
        catch (Exception e)
        {
            this.ThrowTerminatingError(new ErrorRecord(
                e,
                "Base64DecodingError",
                ErrorCategory.InvalidData,
                null));

            return;
        }

        byte[] secret;
        try
        {
            secret = ProtectedData.Unprotect(bytes, null, this.Scope!.Value);
        }
        catch (Exception e)
        {
            this.ThrowTerminatingError(new ErrorRecord(
                e,
                "DecryptionError",
                ErrorCategory.NotSpecified,
                null));

            return;
        }

        string decoded;
        try
        {
            decoded = this.encoding.GetString(secret);
        }
        catch (Exception e)
        {
            this.ThrowTerminatingError(new ErrorRecord(
                e,
                "DecodingError",
                ErrorCategory.NotSpecified,
                null));

            return;
        }

        object result;

        switch (this.ParameterSetName)
        {
            case StringParameterSetName:

                result = decoded;

                break;

            case SecureStringParameterSetName:

#pragma warning disable CA2000
                // The caller must dispose the object when ready.
                var secureString = new SecureString();
#pragma warning restore CA2000

                foreach (var c in decoded)
                {
                    secureString.AppendChar(c);
                }

                secureString.MakeReadOnly();

                result = secureString;

                break;

            default:

                throw new InvalidOperationException($"Unknown parameter set name: \"{this.ParameterSetName}\".");
        }

        this.WriteObject(result);
    }
}