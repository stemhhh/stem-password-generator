using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace StemPasswordGenerator.Services;

public static class PayloadFingerprint
{
    public const string FileName = "payload.stamp";

    public static string FromDirectories(string version, params string[] directories)
    {
        ArgumentNullException.ThrowIfNull(version);
        ArgumentNullException.ThrowIfNull(directories);

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, version);
        foreach (var directory in directories.OrderBy(static value => value, StringComparer.OrdinalIgnoreCase))
        {
            AppendDirectory(hash, directory);
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    public static bool Matches(string stampPath, string expected)
    {
        if (string.IsNullOrWhiteSpace(stampPath) || string.IsNullOrWhiteSpace(expected) || !File.Exists(stampPath))
        {
            return false;
        }

        try
        {
            var stored = File.ReadAllText(stampPath).Trim();
            if (stored.Length != expected.Length)
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(stored),
                Encoding.ASCII.GetBytes(expected));
        }
        catch (IOException)
        {
            return false;
        }
    }

    public static void Write(string stampPath, string fingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stampPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(fingerprint);
        Directory.CreateDirectory(Path.GetDirectoryName(stampPath)!);
        File.WriteAllText(stampPath, fingerprint);
    }

    private static void AppendDirectory(IncrementalHash hash, string directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            Append(hash, "missing:" + (directory ?? string.Empty));
            return;
        }

        Append(hash, "dir:" + directory);
        foreach (var file in Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
                     .OrderBy(static path => path, StringComparer.OrdinalIgnoreCase))
        {
            var info = new FileInfo(file);
            Append(hash, Path.GetRelativePath(directory, file));
            Append(hash, info.Length.ToString(CultureInfo.InvariantCulture));
            Append(hash, info.LastWriteTimeUtc.Ticks.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static void Append(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        hash.AppendData(BitConverter.GetBytes(bytes.Length));
        hash.AppendData(bytes);
    }
}
