using System.Text.Json.Serialization;

namespace StemPasswordGenerator.Models;

public sealed class MailboxProfile
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Label { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public bool IsDefault { get; set; }

    [JsonIgnore]
    public string DisplayLabel
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(Label) && !string.IsNullOrWhiteSpace(Email))
            {
                return $"{Label} · {Email}";
            }

            return string.IsNullOrWhiteSpace(Email) ? Label : Email;
        }
    }
}
