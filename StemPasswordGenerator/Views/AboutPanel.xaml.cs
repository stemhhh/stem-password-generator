using System.Reflection;
using Microsoft.UI.Xaml.Controls;
using StemPasswordGenerator.Services;
using Windows.ApplicationModel;

namespace StemPasswordGenerator.Views;

public sealed partial class AboutPanel : UserControl
{
    public AboutPanel()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        UiStrings.LanguageChanged += OnLanguageChanged;
        ApplyVersion();
    }

    private void OnUnloaded(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        UiStrings.LanguageChanged -= OnLanguageChanged;
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        DispatcherQueue.TryEnqueue(ApplyVersion);
    }

    private void ApplyVersion()
    {
        VersionLabel.Text = UiStrings.Format("Version", GetAppVersion());
    }

    private static string GetAppVersion()
    {
        try
        {
            var version = Package.Current.Id.Version;
            return $"{version.Major}.{version.Minor}.{version.Build}";
        }
        catch (Exception)
        {
            var assemblyVersion = Assembly.GetExecutingAssembly().GetName().Version;
            return assemblyVersion is null
                ? "1.9.47"
                : $"{assemblyVersion.Major}.{assemblyVersion.Minor}.{assemblyVersion.Build}";
        }
    }
}
