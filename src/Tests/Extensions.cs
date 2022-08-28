namespace Tests;

using System;
using System.Security;

public static class Extensions
{
    public static SecureString ToSecureString(this string input)
    {
        var secureString = new SecureString();

        foreach (var c in input)
        {
            secureString.AppendChar(c);
        }

        secureString.MakeReadOnly();

        return secureString;
    }
}