using System.Security.Cryptography;
using System.Text;

namespace StemPasswordGenerator.Services;

public static class AliasGenerator
{
    public static string Generate(string primaryEmail, string aliasDomain, string siteHint)
    {
        var token = CreateToken();
        var site = Sanitize(siteHint);
        var custom = aliasDomain.Trim().TrimStart('@');
        if (!string.IsNullOrWhiteSpace(custom))
        {
            var local = string.IsNullOrEmpty(site) ? token : $"{site}.{token}";
            return $"{local}@{custom}".ToLowerInvariant();
        }

        if (TrySplitEmail(primaryEmail, out var localPart, out var domain))
        {
            var plus = string.IsNullOrEmpty(site) ? token : $"{site}.{token}";
            return $"{localPart}+{plus}@{domain}".ToLowerInvariant();
        }

        return $"{token}@localhost";
    }

    private static string CreateToken()
    {
        var words = WordList.Words;
        var left = words[RandomNumberGenerator.GetInt32(words.Count)];
        var right = words[RandomNumberGenerator.GetInt32(words.Count)];
        var number = RandomNumberGenerator.GetInt32(10, 99);
        return $"{left}.{right}{number}";
    }

    private static string Sanitize(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        if (Uri.TryCreate(value, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
        {
            value = uri.Host.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? uri.Host[4..] : uri.Host;
            var dot = value.IndexOf('.');
            if (dot > 0)
            {
                value = value[..dot];
            }
        }

        var builder = new StringBuilder(value.Length);
        foreach (var character in value.Trim().ToLowerInvariant())
        {
            if (char.IsLetterOrDigit(character))
            {
                builder.Append(character);
            }
            else if (builder.Length > 0 && builder[^1] != '.')
            {
                builder.Append('.');
            }
        }

        return builder.ToString().Trim('.');
    }

    private static bool TrySplitEmail(string email, out string local, out string domain)
    {
        local = string.Empty;
        domain = string.Empty;
        var at = email.Trim().LastIndexOf('@');
        if (at <= 0 || at == email.Trim().Length - 1)
        {
            return false;
        }

        local = email.Trim()[..at];
        domain = email.Trim()[(at + 1)..];
        return local.Length > 0 && domain.Contains('.', StringComparison.Ordinal);
    }
}
