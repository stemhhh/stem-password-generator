using Windows.ApplicationModel.DataTransfer;

namespace StemPasswordGenerator.Services;

public sealed class ClipboardService
{
    public const int DefaultClearSeconds = 30;

    private CancellationTokenSource? _clearCancellation;
    private byte[]? _fingerprint;

    public bool AutoClear { get; set; } = true;

    public int AutoClearSeconds { get; set; } = DefaultClearSeconds;

    public event Action? Cleared;

    public bool TryCopy(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        try
        {
            var package = new DataPackage();
            package.SetText(text);
            var options = new ClipboardContentOptions
            {
                IsAllowedInHistory = false,
                IsRoamable = false
            };

            if (!Clipboard.SetContentWithOptions(package, options))
            {
                return false;
            }

            ScheduleClear(SecretFingerprint.Hash(text));
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public async Task<bool> TryClearIfMatchesAsync(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        return await TryClearIfFingerprintAsync(SecretFingerprint.Hash(text)).ConfigureAwait(true);
    }

    public void ClearNow()
    {
        _clearCancellation?.Cancel();
        WipeFingerprint();
        try
        {
            Clipboard.Clear();
            Cleared?.Invoke();
        }
        catch (Exception)
        {
        }
    }

    private async void ScheduleClear(byte[] fingerprint)
    {
        _clearCancellation?.Cancel();
        _clearCancellation?.Dispose();
        WipeFingerprint();
        _fingerprint = fingerprint;
        if (!AutoClear)
        {
            _clearCancellation = null;
            WipeFingerprint();
            return;
        }

        _clearCancellation = new CancellationTokenSource();
        var token = _clearCancellation.Token;
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(AutoClearSeconds, 5, 120)), token);
            if (await TryClearIfFingerprintAsync(_fingerprint).ConfigureAwait(true))
            {
                Cleared?.Invoke();
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task<bool> TryClearIfFingerprintAsync(byte[]? fingerprint)
    {
        if (fingerprint is not { Length: 32 })
        {
            return false;
        }

        try
        {
            var content = Clipboard.GetContent();
            if (!content.Contains(StandardDataFormats.Text))
            {
                return false;
            }

            var current = await content.GetTextAsync();
            if (!SecretFingerprint.Matches(current, fingerprint))
            {
                return false;
            }

            ClearNow();
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private void WipeFingerprint()
    {
        if (_fingerprint is not null)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(_fingerprint);
            _fingerprint = null;
        }
    }
}
