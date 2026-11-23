using System.Text.RegularExpressions;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class UsbDriveRules
{
    public static readonly string[] FileSystems = ["EXFAT", "FAT32", "NTFS"];

    public static readonly int[] ClusterBytes = [0, 4096, 8192, 16384, 32768, 65536];

    private static readonly Regex LetterPattern = new("^[A-Za-z]:\\\\?$", RegexOptions.Compiled);

    public static string NormalizeLetter(string letter)
    {
        var trimmed = (letter ?? string.Empty).Trim();
        if (trimmed.Length >= 1 && char.IsLetter(trimmed[0]) && (trimmed.Length == 1 || trimmed[1] == ':'))
        {
            return char.ToUpperInvariant(trimmed[0]) + ":";
        }

        throw new ArgumentException("That is not a drive letter.", nameof(letter));
    }

    public static bool IsSafeLetter(string letter, string? systemRoot = null)
    {
        try
        {
            var root = NormalizeLetter(letter) + "\\";
            if (!LetterPattern.IsMatch(root))
            {
                return false;
            }

            var system = Path.GetPathRoot(systemRoot ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            if (string.IsNullOrWhiteSpace(system))
            {
                return true;
            }

            return !string.Equals(Path.GetFullPath(root), Path.GetFullPath(system), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static void EnsureSafe(UsbFormatRequest request, string? systemRoot = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!IsSafeLetter(request.Letter, systemRoot))
        {
            throw new InvalidOperationException("Stem will not format the Windows system drive.");
        }

        var fs = (request.FileSystem ?? string.Empty).ToUpperInvariant();
        if (Array.IndexOf(FileSystems, fs) < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Choose FAT32, exFAT, or NTFS.");
        }
    }

    public static string SanitizeLabel(string? label, string fileSystem)
    {
        var max = fileSystem.Equals("NTFS", StringComparison.OrdinalIgnoreCase) ? 32 : 11;
        var builder = new System.Text.StringBuilder(max);
        foreach (var character in label ?? string.Empty)
        {
            if (builder.Length >= max)
            {
                break;
            }

            if (char.IsLetterOrDigit(character) || character is '_' or '-')
            {
                builder.Append(character);
            }
        }

        var clean = builder.ToString().Trim();
        return string.IsNullOrEmpty(clean) ? "STEM" : clean;
    }

    public static string BuildFormatArguments(UsbFormatRequest request, string? systemRoot = null)
    {
        EnsureSafe(request, systemRoot);
        var letter = NormalizeLetter(request.Letter);
        var fs = request.FileSystem.ToUpperInvariant();
        var args = $"{letter} /FS:{fs} /Y /X";
        if (request.QuickFormat)
        {
            args += " /Q";
        }

        args += $" /V:{SanitizeLabel(request.Label, fs)}";
        if (request.ClusterBytes is > 0 and var cluster)
        {
            args += $" /A:{FormatCluster(cluster)}";
        }

        return args;
    }

    public static bool RecommendsExFat(long totalBytes) => totalBytes > 32L * 1024 * 1024 * 1024;

    private static string FormatCluster(int bytes) => bytes switch
    {
        >= 1024 * 1024 => $"{bytes / (1024 * 1024)}K",
        >= 1024 => bytes % 1024 == 0 ? $"{bytes / 1024}K" : bytes.ToString(),
        _ => bytes.ToString()
    };
}
