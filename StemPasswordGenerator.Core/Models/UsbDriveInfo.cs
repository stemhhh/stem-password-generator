namespace StemPasswordGenerator.Models;

public sealed class UsbDriveInfo
{
    public string Letter { get; init; } = string.Empty;

    public string Label { get; init; } = string.Empty;

    public string FileSystem { get; init; } = string.Empty;

    public long TotalBytes { get; init; }

    public long FreeBytes { get; init; }

    public bool IsReady { get; init; }

    public bool HasStemKey { get; init; }

    public string DisplayLabel
    {
        get
        {
            var name = string.IsNullOrWhiteSpace(Label) ? Letter : $"{Letter}  {Label}";
            var size = TotalBytes <= 0 ? "" : $" · {FormatSize(TotalBytes)}";
            var fs = string.IsNullOrWhiteSpace(FileSystem) ? "" : $" · {FileSystem}";
            var key = HasStemKey ? " · Stem" : "";
            return $"{name}{size}{fs}{key}";
        }
    }

    private static string FormatSize(long bytes)
    {
        const double giga = 1024d * 1024d * 1024d;
        const double mega = 1024d * 1024d;
        if (bytes >= giga)
        {
            return $"{bytes / giga:0.0} GB";
        }

        return $"{bytes / mega:0} MB";
    }
}

public sealed class UsbFormatRequest
{
    public string Letter { get; init; } = string.Empty;

    public string FileSystem { get; init; } = "EXFAT";

    public string Label { get; init; } = string.Empty;

    public bool QuickFormat { get; init; } = true;

    public int? ClusterBytes { get; init; }
}
