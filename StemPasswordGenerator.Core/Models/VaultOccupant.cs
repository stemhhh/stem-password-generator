namespace StemPasswordGenerator.Models;

public sealed class VaultOccupant
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string DisplayName { get; set; } = string.Empty;

    public string FolderName { get; set; } = string.Empty;

    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset LastUnlockedUtc { get; set; }
}

public sealed class OccupantCatalog
{
    public int Version { get; set; } = 1;

    public Guid? ActiveId { get; set; }

    public List<VaultOccupant> Occupants { get; set; } = [];
}
