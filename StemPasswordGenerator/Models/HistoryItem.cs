using StemPasswordGenerator.Services;
using StemPasswordGenerator.ViewModels;

namespace StemPasswordGenerator.Models;

public sealed class HistoryItem
{
    public HistoryItem(string secret, GeneratorMode mode, DateTime created, Action<HistoryItem> copy)
    {
        Secret = secret;
        Mode = mode;
        Created = created;
        Preview = secret.Length <= 32 ? secret : secret[..30] + "…";
        CopyCommand = new RelayCommand(() => copy(this));
        RefreshLanguage();
    }

    public string Secret { get; }

    public string Preview { get; }

    public GeneratorMode Mode { get; }

    public DateTime Created { get; }

    public string ModeLabel { get; private set; } = string.Empty;

    public string TimeLabel { get; private set; } = string.Empty;

    public string MetaLabel { get; private set; } = string.Empty;

    public RelayCommand CopyCommand { get; }

    public void RefreshLanguage()
    {
        ModeLabel = Mode switch
        {
            GeneratorMode.Passphrase => UiStrings.Get("Passphrase"),
            GeneratorMode.Pin => UiStrings.Get("PIN"),
            _ => UiStrings.Get("Password")
        };
        TimeLabel = Created.ToString("t");
        MetaLabel = $"{ModeLabel} · {TimeLabel}";
    }
}
