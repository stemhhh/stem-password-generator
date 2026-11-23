using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using StemPasswordGenerator.Services;
using StemPasswordGenerator.ViewModels;

namespace StemPasswordGenerator.Views;

public sealed partial class VaultPanel : UserControl
{
    private VaultViewModel? _boundViewModel;
    private bool _syncingEditorPassword;
    private bool? _compactVault;

    public VaultPanel()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
        Unloaded += OnUnloaded;
        UiStrings.LanguageChanged += OnLanguageChanged;
        ApplyKindLanguage();
    }

    private void WorkspaceSplit_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        var compact = FluidLayout.IsCompactVault(e.NewSize.Width);
        var wideListMax = e.NewSize.Width >= FluidLayout.UltraWidth ? 560 : 480;
        if (_compactVault == compact && !compact)
        {
            VaultListColumn.MaxWidth = wideListMax;
            return;
        }

        if (_compactVault == compact)
        {
            return;
        }

        _compactVault = compact;
        if (compact)
        {
            VaultListColumn.Width = new GridLength(1, GridUnitType.Star);
            VaultListColumn.MaxWidth = double.PositiveInfinity;
            VaultEditorColumn.Width = new GridLength(0);
            VaultListRow.Height = GridLength.Auto;
            VaultEditorRow.Height = new GridLength(1, GridUnitType.Star);
            Grid.SetColumn(VaultListPane, 0);
            Grid.SetRow(VaultListPane, 0);
            Grid.SetColumnSpan(VaultListPane, 2);
            Grid.SetRowSpan(VaultListPane, 1);
            Grid.SetColumn(VaultEditorPane, 0);
            Grid.SetRow(VaultEditorPane, 1);
            Grid.SetColumnSpan(VaultEditorPane, 2);
            Grid.SetRowSpan(VaultEditorPane, 1);
            VaultListPane.MaxHeight = 280;
            VaultListPane.BorderThickness = new Thickness(0, 0, 0, 1);
            return;
        }

        VaultListColumn.Width = new GridLength(0.9, GridUnitType.Star);
        VaultListColumn.MaxWidth = wideListMax;
        VaultEditorColumn.Width = new GridLength(2.2, GridUnitType.Star);
        VaultListRow.Height = new GridLength(1, GridUnitType.Star);
        VaultEditorRow.Height = new GridLength(0);
        Grid.SetColumn(VaultListPane, 0);
        Grid.SetRow(VaultListPane, 0);
        Grid.SetColumnSpan(VaultListPane, 1);
        Grid.SetRowSpan(VaultListPane, 2);
        Grid.SetColumn(VaultEditorPane, 1);
        Grid.SetRow(VaultEditorPane, 0);
        Grid.SetColumnSpan(VaultEditorPane, 1);
        Grid.SetRowSpan(VaultEditorPane, 2);
        VaultListPane.MaxHeight = double.PositiveInfinity;
        VaultListPane.BorderThickness = new Thickness(0, 0, 1, 0);
    }

    private VaultViewModel? ViewModel => DataContext as VaultViewModel;

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        DispatcherQueue.TryEnqueue(ApplyKindLanguage);
    }

    private void ApplyKindLanguage()
    {
        KindLoginItem.Content = UiStrings.Get("KindLogin");
        KindAliasItem.Content = UiStrings.Get("KindAliasLong");
        KindCardItem.Content = UiStrings.Get("KindCardLong");
        KindNoteItem.Content = UiStrings.Get("KindNote");
        KindIdentityItem.Content = UiStrings.Get("KindIdentity");
        KindRecoveryItem.Content = UiStrings.Get("KindRecoveryLong");
        KindWifiItem.Content = UiStrings.Get("KindWifiLong");
        KindSecretItem.Content = UiStrings.Get("KindSecretLong");
        WifiWpaItem.Content = UiStrings.Get("WifiWpa");
        WifiWepItem.Content = UiStrings.Get("WifiWep");
        WifiOpenItem.Content = UiStrings.Get("WifiOpen");
    }

    private void OnDataContextChanged(FrameworkElement sender, DataContextChangedEventArgs args)
    {
        if (_boundViewModel is not null)
        {
            _boundViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        }

        _boundViewModel = args.NewValue as VaultViewModel;
        if (_boundViewModel is not null)
        {
            _boundViewModel.PropertyChanged += OnViewModelPropertyChanged;
            SyncEditorPasswordBox();
        }
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_boundViewModel is not null)
        {
            _boundViewModel.PropertyChanged -= OnViewModelPropertyChanged;
            _boundViewModel = null;
        }

        UiStrings.LanguageChanged -= OnLanguageChanged;
    }

    private void OnViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(VaultViewModel.ShowSetup)
            or nameof(VaultViewModel.ShowUnlock)
            or nameof(VaultViewModel.ShowWorkspace)
            or nameof(VaultViewModel.MasterPassword)
            or nameof(VaultViewModel.ConfirmPassword))
        {
            if (string.IsNullOrEmpty(ViewModel?.MasterPassword))
            {
                SetupPasswordBox.Password = string.Empty;
                UnlockPasswordBox.Password = string.Empty;
            }
            else if (UnlockPasswordBox.Password != ViewModel.MasterPassword)
            {
                UnlockPasswordBox.Password = ViewModel.MasterPassword;
            }

            if (string.IsNullOrEmpty(ViewModel?.ConfirmPassword))
            {
                SetupConfirmBox.Password = string.Empty;
            }
        }

        if (e.PropertyName is nameof(VaultViewModel.EditPassword) or nameof(VaultViewModel.IsPasswordVisible))
        {
            SyncEditorPasswordBox();
        }
    }

    private void SyncEditorPasswordBox()
    {
        if (ViewModel is null || _syncingEditorPassword)
        {
            return;
        }

        _syncingEditorPassword = true;
        try
        {
            if (EditorPasswordBox.Password != ViewModel.EditPassword)
            {
                EditorPasswordBox.Password = ViewModel.EditPassword;
            }
        }
        finally
        {
            _syncingEditorPassword = false;
        }
    }

    private void SetupPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not null && sender is PasswordBox box)
        {
            ViewModel.MasterPassword = box.Password;
        }
    }

    private void SetupConfirmBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not null && sender is PasswordBox box)
        {
            ViewModel.ConfirmPassword = box.Password;
        }
    }

    private void HumanKey_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Content: string digit } && digit.Length > 0)
        {
            ViewModel?.SubmitHumanDigitCommand.Execute(digit);
        }
    }

    private void UnlockPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not null && sender is PasswordBox box)
        {
            ViewModel.MasterPassword = box.Password;
        }
    }

    private void EditorPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_syncingEditorPassword || ViewModel is null || sender is not PasswordBox box)
        {
            return;
        }

        _syncingEditorPassword = true;
        try
        {
            ViewModel.EditPassword = box.Password;
        }
        finally
        {
            _syncingEditorPassword = false;
        }
    }
}
