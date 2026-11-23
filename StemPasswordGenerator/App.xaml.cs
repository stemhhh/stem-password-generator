using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;
using StemPasswordGenerator.Helpers;
using StemPasswordGenerator.Views;

namespace StemPasswordGenerator;

public partial class App : Application
{
    private MainWindow? _window;

    public App()
    {
        InitializeComponent();
        UnhandledException += OnUnhandledException;
        RuntimeHardening.ApplyProcessMitigations();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            var current = AppInstance.GetCurrent();
            var registered = AppInstance.FindOrRegisterForKey("Stem.StemPasswordGenerator");
            if (!registered.IsCurrent)
            {
                registered.RedirectActivationToAsync(current.GetActivatedEventArgs()).AsTask().GetAwaiter().GetResult();
                Environment.Exit(0);
                return;
            }

            registered.Activated += OnRedirectedActivation;
            _window = new MainWindow();
            _window.BringToFront();
        }
        catch (Exception exception)
        {
            LogCrash(exception);
            throw;
        }
    }

    private void OnRedirectedActivation(object? sender, AppActivationArguments args)
    {
        _window?.DispatcherQueue.TryEnqueue(() => _window?.BringToFront());
    }

    private void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        LogCrash(e.Exception);
    }

    private static void LogCrash(Exception exception)
    {
        try
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "StemPasswordGenerator",
                "launch-error.log");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(
                path,
                $"{DateTime.Now:O}{Environment.NewLine}{exception.GetType().FullName}{Environment.NewLine}{exception.StackTrace}");
        }
        catch
        {
        }
    }
}
