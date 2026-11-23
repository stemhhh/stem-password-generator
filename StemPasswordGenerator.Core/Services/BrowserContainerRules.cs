using System.Text.RegularExpressions;

namespace StemPasswordGenerator.Services;

public static class BrowserContainerRules
{
    public const int MaxIdLength = 64;
    public const string FirefoxContainerPrefix = "firefox-container-";
    public const string ChromiumProfilePrefix = "chromium-profile-";

    private static readonly Regex ChromiumProfilePattern = new(
        @"^chromium-profile-([a-z]{2,16})-(Default|Profile [1-9]\d{0,2})$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static string Normalize(string? cookieStoreId)
    {
        if (string.IsNullOrWhiteSpace(cookieStoreId))
        {
            return string.Empty;
        }

        var value = cookieStoreId.Trim();
        if (value.Length > MaxIdLength
            || value is "0" or "firefox-default"
            || value.Contains("private", StringComparison.OrdinalIgnoreCase)
            || value.Contains('\\')
            || value.Contains('/'))
        {
            return string.Empty;
        }

        if (value.StartsWith(FirefoxContainerPrefix, StringComparison.Ordinal))
        {
            return NormalizeFirefox(value);
        }

        return ChromiumProfilePattern.IsMatch(value) ? value : string.Empty;
    }

    public static string BindOnSave(string? cookieStoreId) => Normalize(cookieStoreId);

    public static bool IsBound(string? cookieStoreId) => Normalize(cookieStoreId).Length > 0;

    public static string NumberLabel(string? cookieStoreId)
    {
        var id = Normalize(cookieStoreId);
        if (id.StartsWith(FirefoxContainerPrefix, StringComparison.Ordinal))
        {
            return id[FirefoxContainerPrefix.Length..];
        }

        return string.Empty;
    }

    public static string DisplayLabel(string? cookieStoreId)
    {
        var id = Normalize(cookieStoreId);
        if (id.Length == 0)
        {
            return string.Empty;
        }

        if (id.StartsWith(FirefoxContainerPrefix, StringComparison.Ordinal))
        {
            return UiStrings.Format("FirefoxContainerName", id[FirefoxContainerPrefix.Length..]);
        }

        var match = ChromiumProfilePattern.Match(id);
        if (!match.Success)
        {
            return string.Empty;
        }

        return UiStrings.Format("ChromiumProfileName", PrettyBrowser(match.Groups[1].Value), match.Groups[2].Value);
    }

    public static bool CanFill(string? itemContainer, string? tabContainer)
    {
        var item = Normalize(itemContainer);
        var tab = Normalize(tabContainer);
        if (item.Length == 0)
        {
            return true;
        }

        return string.Equals(item, tab, StringComparison.Ordinal);
    }

    public static bool WarnUnbound(string? itemContainer, string? tabContainer) =>
        Normalize(itemContainer).Length == 0 && Normalize(tabContainer).Length > 0;

    public static string ForNativeRequest(string? extensionContainer, string? parentImage, string? commandLine, bool incognito = false)
    {
        if (IsFirefoxFamily(parentImage))
        {
            return incognito ? string.Empty : Normalize(extensionContainer);
        }

        if (IsChromiumFamily(parentImage))
        {
            return incognito ? string.Empty : ChromiumId(parentImage, commandLine);
        }

        return Normalize(extensionContainer);
    }

    public static string ChromiumId(string? parentImage, string? commandLine)
    {
        if (IsIncognitoCommandLine(commandLine))
        {
            return string.Empty;
        }

        var browser = BrowserKey(parentImage);
        var directory = ParseProfileDirectory(commandLine);
        if (browser.Length == 0 || directory.Length == 0)
        {
            return string.Empty;
        }

        return Normalize($"{ChromiumProfilePrefix}{browser}-{directory}");
    }

    public static string ParseProfileDirectory(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return "Default";
        }

        if (IsIncognitoCommandLine(commandLine))
        {
            return string.Empty;
        }

        const string marker = "--profile-directory=";
        var start = commandLine.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
        {
            return "Default";
        }

        start += marker.Length;
        if (start >= commandLine.Length)
        {
            return string.Empty;
        }

        var rest = commandLine[start..];
        string value;
        if (rest.StartsWith('"'))
        {
            var end = rest.IndexOf('"', 1);
            value = end < 0 ? rest[1..] : rest[1..end];
        }
        else if (rest.StartsWith("Profile ", StringComparison.Ordinal))
        {
            var i = 8;
            while (i < rest.Length && char.IsAsciiDigit(rest[i]))
            {
                i++;
            }

            value = rest[..i];
        }
        else
        {
            var end = rest.IndexOfAny([' ', '\t']);
            value = end < 0 ? rest : rest[..end];
        }

        value = value.Trim();
        if (value is "Default")
        {
            return value;
        }

        if (value.StartsWith("Profile ", StringComparison.Ordinal)
            && value.Length is >= 9 and <= 14)
        {
            for (var i = 8; i < value.Length; i++)
            {
                if (!char.IsAsciiDigit(value[i]))
                {
                    return string.Empty;
                }
            }

            return value[8] != '0' ? value : string.Empty;
        }

        return string.Empty;
    }

    public static bool IsIncognitoCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return false;
        }

        return commandLine.Contains("--incognito", StringComparison.OrdinalIgnoreCase)
            || commandLine.Contains("-inprivate", StringComparison.OrdinalIgnoreCase);
    }

    public static string HiddenInOtherContainerMessage { get; } =
        "A login for this site is saved in another browser profile or Firefox container.";

    public static string WrongContainerMessage { get; } =
        "That login belongs to another browser profile or Firefox container.";

    public static string UnboundWarning { get; } =
        "This login is not bound to this browser profile or Firefox container.";

    private static string NormalizeFirefox(string value)
    {
        if (value.Length <= FirefoxContainerPrefix.Length
            || value.Length > FirefoxContainerPrefix.Length + 6)
        {
            return string.Empty;
        }

        for (var i = FirefoxContainerPrefix.Length; i < value.Length; i++)
        {
            if (!char.IsAsciiDigit(value[i]))
            {
                return string.Empty;
            }
        }

        return value;
    }

    private static bool IsFirefoxFamily(string? imagePath)
    {
        var name = FileName(imagePath);
        return name is "firefox.exe" or "waterfox.exe";
    }

    private static bool IsChromiumFamily(string? imagePath)
    {
        var name = FileName(imagePath);
        if (IsFirefoxFamily(imagePath) || name is "" or "stempasswordgenerator.exe")
        {
            return false;
        }

        return name is "brave.exe" or "chrome.exe" or "msedge.exe" or "vivaldi.exe" or "opera.exe" or "chromium.exe" or "browser.exe";
    }

    private static string BrowserKey(string? imagePath)
    {
        var name = Path.GetFileNameWithoutExtension(imagePath ?? string.Empty).ToLowerInvariant();
        if (name.Length is < 2 or > 16)
        {
            return string.Empty;
        }

        foreach (var c in name)
        {
            if (c is < 'a' or > 'z')
            {
                return string.Empty;
            }
        }

        return name switch
        {
            "msedgewebview2" => "msedge",
            _ => name
        };
    }

    private static string PrettyBrowser(string key) => key switch
    {
        "chrome" => "Chrome",
        "chromium" => "Chromium",
        "msedge" => "Edge",
        "brave" => "Brave",
        "opera" => "Opera",
        "vivaldi" => "Vivaldi",
        "arc" => "Arc",
        _ => string.Concat(char.ToUpperInvariant(key[0]), key[1..])
    };

    private static string FileName(string? imagePath) =>
        Path.GetFileName(imagePath ?? string.Empty).ToLowerInvariant();
}
