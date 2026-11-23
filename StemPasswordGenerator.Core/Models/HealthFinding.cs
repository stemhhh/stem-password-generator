using StemPasswordGenerator.Services;

namespace StemPasswordGenerator.Models;

public sealed class HealthFinding
{
    public required Guid ItemId { get; init; }

    public required string Title { get; init; }

    public required string Detail { get; init; }

    public required string Severity { get; init; }

    public string SeverityLabel => UiStrings.Get("Severity" + Severity);
}
