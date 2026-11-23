namespace StemPasswordGenerator.Models;

public static class MediaCategory
{
    public const string Photo = "photo";
    public const string Video = "video";
    public const string Audio = "audio";
    public const string File = "file";
}

public sealed class MediaEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Category { get; set; } = MediaCategory.File;

    public string Title { get; set; } = string.Empty;

    public string Folder { get; set; } = string.Empty;

    public string OriginalName { get; set; } = string.Empty;

    public string ContentType { get; set; } = "application/octet-stream";

    public long ByteLength { get; set; }

    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset ModifiedUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? LastUsedUtc { get; set; }
}
