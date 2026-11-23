using System.Text.Json.Serialization;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = false)]
[JsonSerializable(typeof(VaultDocument))]
[JsonSerializable(typeof(VaultSettings))]
[JsonSerializable(typeof(VaultItem))]
[JsonSerializable(typeof(VaultAttachment))]
[JsonSerializable(typeof(PasswordHistoryEntry))]
[JsonSerializable(typeof(List<PasswordHistoryEntry>))]
[JsonSerializable(typeof(MediaEntry))]
[JsonSerializable(typeof(List<MediaEntry>))]
[JsonSerializable(typeof(AuditEvent))]
[JsonSerializable(typeof(List<AuditEvent>))]
[JsonSerializable(typeof(MailboxProfile))]
[JsonSerializable(typeof(OccupantCatalog))]
[JsonSerializable(typeof(VaultOccupant))]
internal sealed partial class VaultJsonContext : JsonSerializerContext
{
}
