using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using StemPasswordGenerator.ViewModels;

namespace StemPasswordGenerator.Views;

public sealed partial class UsbKeyPanel : UserControl
{
    public UsbKeyPanel()
    {
        InitializeComponent();
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        (DataContext as VaultViewModel)?.RefreshUsbDrives();
    }
}
