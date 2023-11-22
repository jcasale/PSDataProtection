namespace Tests;

using System;
using System.Runtime.InteropServices;
using System.Security;

public static class Extensions
{
    public static string ToPlainString(this SecureString input)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input));
        }

        var ptr = IntPtr.Zero;
        try
        {
            ptr = Marshal.SecureStringToGlobalAllocUnicode(input);

            return Marshal.PtrToStringUni(ptr);
        }
        finally
        {
            if (ptr != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }
    }

    public static SecureString ToSecureString(this string input)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input));
        }

        var secureString = new SecureString();

        foreach (var c in input)
        {
            secureString.AppendChar(c);
        }

        secureString.MakeReadOnly();

        return secureString;
    }
}