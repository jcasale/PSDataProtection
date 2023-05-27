namespace PSDataProtection;

using System;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

[Cmdlet(VerbsCommon.New, "DataProtectionSecret")]
[OutputType(typeof(string))]
public class NewDataProtectionSecretCommand : PSCmdlet
{
    private readonly System.Text.UTF8Encoding encoding = new();

    [Parameter(
        Position = 0,
        Mandatory = true,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        HelpMessage = "Specifies the data to encrypt and encode to a base64 string.")]
    [ValidateNotNullOrEmpty]
    public SecureString SecureString { get; set; }

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
        IntPtr bString;
        try
        {
            bString = Marshal.SecureStringToBSTR(this.SecureString);
        }
        catch (Exception e)
        {
            this.ThrowTerminatingError(new ErrorRecord(
                e,
                "SecureStringToBinaryStringError",
                ErrorCategory.InvalidData,
                null));

            return;
        }

        string insecurePassword;
        try
        {
            insecurePassword = Marshal.PtrToStringBSTR(bString);
        }
        catch (Exception e)
        {
            this.ThrowTerminatingError(new ErrorRecord(
                e,
                "BinaryStringToManagedStringError",
                ErrorCategory.InvalidData,
                null));

            return;
        }
        finally
        {
            Marshal.ZeroFreeBSTR(bString);
        }

        if (string.IsNullOrWhiteSpace(insecurePassword))
        {
            this.ThrowTerminatingError(new ErrorRecord(
                new InvalidOperationException("The secure string was empty."),
                "EmptyPassword",
                ErrorCategory.InvalidData,
                null));

            return;
        }

        byte[] bytes;
        try
        {
            bytes = this.encoding.GetBytes(insecurePassword);
        }
        catch (Exception e)
        {
            this.ThrowTerminatingError(new ErrorRecord(
                e,
                "BinaryEncodingError",
                ErrorCategory.InvalidData,
                null));

            return;
        }

        byte[] secret;
        try
        {
            secret = ProtectedData.Protect(bytes, null, this.Scope!.Value);
        }
        catch (Exception e)
        {
            this.ThrowTerminatingError(new ErrorRecord(
                e,
                "ProtectionError",
                ErrorCategory.NotSpecified,
                null));

            return;
        }

        string encoded;
        try
        {
            encoded = Convert.ToBase64String(secret);
        }
        catch (Exception e)
        {
            this.ThrowTerminatingError(new ErrorRecord(
                e,
                "Base64EncodingError",
                ErrorCategory.NotSpecified,
                null));

            return;
        }

        this.WriteObject(encoded);
    }
}