using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public sealed class PendingVaultHold : IDisposable
{
    private VaultDocument? _document;

    public PendingVaultHold(VaultDocument document)
    {
        _document = document ?? throw new ArgumentNullException(nameof(document));
    }

    public bool HasPayload => _document is not null;

    public VaultDocument Take()
    {
        var document = _document ?? throw new InvalidOperationException("The pending vault payload was already consumed.");
        _document = null;
        return document;
    }

    public void Dispose()
    {
        if (_document is null)
        {
            return;
        }

        VaultCryptography.ClearDocument(_document);
        _document = null;
    }
}
