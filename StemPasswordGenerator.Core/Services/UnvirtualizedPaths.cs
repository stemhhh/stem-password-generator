using System.Runtime.InteropServices;

namespace StemPasswordGenerator.Services;

public static class UnvirtualizedPaths
{
    private static readonly Guid FolderIdLocalAppData = new("F1B32785-6FBA-4FCF-9D55-7B8E7F157091");
    private const uint KfNoPackageRedirection = 0x00010000;

    public static string LocalAppData()
    {
        if (OperatingSystem.IsWindows() && TryGetLocalAppData(out var path))
        {
            return path;
        }

        return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    public static string StemRoot() => Path.Combine(LocalAppData(), "StemPasswordGenerator");

    public static bool TryGetLocalAppData(out string path)
    {
        path = string.Empty;
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        var folder = FolderIdLocalAppData;
        var hr = SHGetKnownFolderPath(ref folder, KfNoPackageRedirection, IntPtr.Zero, out var pointer);
        if (hr != 0 || pointer == IntPtr.Zero)
        {
            return false;
        }

        try
        {
            path = Marshal.PtrToStringUni(pointer) ?? string.Empty;
            return path.Length > 0;
        }
        finally
        {
            Marshal.FreeCoTaskMem(pointer);
        }
    }

    [DllImport("shell32.dll")]
    private static extern int SHGetKnownFolderPath(ref Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);
}
