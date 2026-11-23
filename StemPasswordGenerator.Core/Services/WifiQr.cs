using System.Text;

namespace StemPasswordGenerator.Services;

public static class WifiQr
{
    public const string Wpa = "WPA";
    public const string Wep = "WEP";
    public const string Open = "nopass";

    public static string NormalizeSecurity(string? security)
    {
        var value = (security ?? string.Empty).Trim();
        if (value.Equals(Wep, StringComparison.OrdinalIgnoreCase))
        {
            return Wep;
        }

        if (value.Equals(Open, StringComparison.OrdinalIgnoreCase)
            || value.Equals("open", StringComparison.OrdinalIgnoreCase)
            || value.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            return Open;
        }

        return Wpa;
    }

    public static bool IsOpen(string? security) => NormalizeSecurity(security) == Open;

    public static string Payload(string ssid, string password, string? security, bool hidden = false)
    {
        var type = NormalizeSecurity(security);
        var builder = new StringBuilder("WIFI:T:");
        builder.Append(type);
        builder.Append(";S:");
        builder.Append(Escape(ssid ?? string.Empty));
        if (type != Open)
        {
            builder.Append(";P:");
            builder.Append(Escape(password ?? string.Empty));
        }

        if (hidden)
        {
            builder.Append(";H:true");
        }

        builder.Append(";;");
        return builder.ToString();
    }

    private static string Escape(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var character in value)
        {
            if (character is '\\' or ';' or ',' or ':' or '"')
            {
                builder.Append('\\');
            }

            builder.Append(character);
        }

        return builder.ToString();
    }
}
