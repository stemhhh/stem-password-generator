using System.Security.Cryptography;

namespace StemPasswordGenerator.Services;

internal static class HumanPresenceSkipFile
{
    private static readonly byte[] Entropy = "STEM-HUMAN-SKIP-v1"u8.ToArray();

    public static string Path => System.IO.Path.Combine(UnvirtualizedPaths.StemRoot(), "human-skip.bin");

    public static DateTimeOffset? Read()
    {
        try
        {
            if (!File.Exists(Path))
            {
                return null;
            }

            var packed = File.ReadAllBytes(Path);
            var ticks = ProtectedData.Unprotect(packed, Entropy, DataProtectionScope.CurrentUser);
            if (ticks.Length != 8)
            {
                return null;
            }

            return new DateTimeOffset(BitConverter.ToInt64(ticks, 0), TimeSpan.Zero);
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static void Write(DateTimeOffset utc)
    {
        try
        {
            Directory.CreateDirectory(UnvirtualizedPaths.StemRoot());
            var ticks = BitConverter.GetBytes(utc.UtcTicks);
            var packed = ProtectedData.Protect(ticks, Entropy, DataProtectionScope.CurrentUser);
            CryptographicOperations.ZeroMemory(ticks);
            File.WriteAllBytes(Path, packed);
        }
        catch (Exception)
        {
        }
    }

    public static void Clear()
    {
        try
        {
            if (File.Exists(Path))
            {
                File.Delete(Path);
            }
        }
        catch (Exception)
        {
        }
    }
}
