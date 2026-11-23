namespace StemPasswordGenerator.Models;

public sealed class VaultDocument
{
    public int Version { get; set; } = 2;

    public VaultSettings Settings { get; set; } = new();

    public List<VaultItem> Items { get; set; } = [];

    public List<MediaEntry> Media { get; set; } = [];

    public List<AuditEvent> Audit { get; set; } = [];
}
