using System.ComponentModel;
using System.Runtime.CompilerServices;
using StemPasswordGenerator.Services;
using StemPasswordGenerator.ViewModels;

namespace StemPasswordGenerator.Models;

public sealed class PasswordHistoryRow : INotifyPropertyChanged
{
    private bool _isVisible;

    public PasswordHistoryRow(
        PasswordHistoryEntry entry,
        Action<PasswordHistoryRow> copy,
        Action<PasswordHistoryRow> restore)
    {
        Password = entry.Password;
        ReplacedUtc = entry.ReplacedUtc;
        CopyCommand = new RelayCommand(() => copy(this));
        RestoreCommand = new RelayCommand(() => restore(this));
        ToggleCommand = new RelayCommand(() => IsVisible = !IsVisible);
        RefreshLanguage();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public string Password { get; }

    public DateTimeOffset ReplacedUtc { get; }

    public bool IsVisible
    {
        get => _isVisible;
        set
        {
            if (_isVisible == value)
            {
                return;
            }

            _isVisible = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(Display));
            OnPropertyChanged(nameof(RevealLabel));
        }
    }

    public string Display => IsVisible ? Password : new string('\u2022', Math.Clamp(Password.Length, 8, 20));

    public string WhenLabel { get; private set; } = string.Empty;

    public string RevealLabel => IsVisible ? UiStrings.Get("Hide") : UiStrings.Get("Show");

    public RelayCommand CopyCommand { get; }

    public RelayCommand RestoreCommand { get; }

    public RelayCommand ToggleCommand { get; }

    public void RefreshLanguage()
    {
        WhenLabel = UiStrings.Format("PasswordHistoryWhen", ReplacedUtc.ToLocalTime().ToString("yyyy-MM-dd"));
        OnPropertyChanged(nameof(WhenLabel));
        OnPropertyChanged(nameof(RevealLabel));
    }

    public void Hide() => IsVisible = false;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
