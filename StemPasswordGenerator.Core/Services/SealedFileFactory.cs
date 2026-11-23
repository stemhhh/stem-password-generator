using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class SealedFileFactory
{
    public static VaultItem CreateNote(string fileName, byte[] data, string notes)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (!VaultItemRules.IsAllowedAttachmentSize(data.Length))
        {
            throw new ArgumentOutOfRangeException(nameof(data), "The file is empty or larger than the vault attachment limit.");
        }

        var name = Path.GetFileName(fileName);
        if (string.IsNullOrWhiteSpace(name))
        {
            name = "file";
        }

        return new VaultItem
        {
            Kind = VaultItemKind.Note,
            Title = name,
            Notes = string.IsNullOrWhiteSpace(notes) ? name : notes.Trim(),
            Attachments =
            [
                new VaultAttachment
                {
                    FileName = name,
                    ContentType = VaultItemRules.ContentTypeFor(name),
                    Data = data.ToArray()
                }
            ]
        };
    }
}
