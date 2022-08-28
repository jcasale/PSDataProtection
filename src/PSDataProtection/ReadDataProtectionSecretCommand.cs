namespace PSDataProtection;

using System;
using System.Management.Automation;
using System.Security.Cryptography;

[Cmdlet(VerbsCommunications.Read, "DataProtectionSecret")]
[OutputType(typeof(string))]
public class ReadDataProtectionSecretCommand : PSCmdlet
{
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
                "Base64DecodingError",
                ErrorCategory.NotSpecified,
                null));

            return;
        }

        this.WriteObject(decoded);
    }
}