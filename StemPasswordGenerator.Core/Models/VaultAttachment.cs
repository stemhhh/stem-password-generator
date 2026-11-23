namespace StemPasswordGenerator.Models;

public sealed class VaultAttachment
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string FileName { get; set; } = string.Empty;

    public string ContentType { get; set; } = "application/octet-stream";

    public byte[] Data { get; set; } = [];
}
