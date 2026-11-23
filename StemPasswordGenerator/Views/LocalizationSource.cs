using System.ComponentModel;
using StemPasswordGenerator.Services;

namespace StemPasswordGenerator.Views;

public sealed class LocalizationSource : INotifyPropertyChanged
{
    public LocalizationSource()
    {
        UiStrings.LanguageChanged += (_, _) => Refresh();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public string this[string key] => UiStrings.Get(key);

    public void Refresh()
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }
}
