namespace StemPasswordGenerator.Models;

public sealed class PasswordHistoryEntry
{
    public string Password { get; set; } = string.Empty;

    public DateTimeOffset ReplacedUtc { get; set; } = DateTimeOffset.UtcNow;
}
