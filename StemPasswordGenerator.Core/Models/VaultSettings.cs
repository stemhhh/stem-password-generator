namespace StemPasswordGenerator.Models;

public sealed class VaultSettings
{
    public string PrimaryEmail { get; set; } = string.Empty;

    public string AliasDomain { get; set; } = string.Empty;

    public List<string> Mailboxes { get; set; } = [];

    public List<MailboxProfile> Profiles { get; set; } = [];

    public byte[]? MediaKeyWrap { get; set; }

    public DateTimeOffset? MasterChangedUtc { get; set; }

    public DateTimeOffset? ClockFloorUtc { get; set; }
}
