using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using StemPasswordGenerator.ViewModels;

namespace StemPasswordGenerator.Views;

public sealed partial class CipherPanel : UserControl
{
    private CipherViewModel? _boundViewModel;
    private bool _syncing;

    public CipherPanel()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
        Unloaded += OnUnloaded;
    }

    private void OnDataContextChanged(FrameworkElement sender, DataContextChangedEventArgs args)
    {
        if (_boundViewModel is not null)
        {
            _boundViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        }

        _boundViewModel = args.NewValue as CipherViewModel;
        if (_boundViewModel is not null)
        {
            _boundViewModel.PropertyChanged += OnViewModelPropertyChanged;
            SyncBoxes();
        }
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_boundViewModel is not null)
        {
            _boundViewModel.PropertyChanged -= OnViewModelPropertyChanged;
            _boundViewModel = null;
        }
    }

    private void OnViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(CipherViewModel.Password) or nameof(CipherViewModel.ConfirmPassword))
        {
            SyncBoxes();
        }
    }

    private void SyncBoxes()
    {
        if (_syncing || _boundViewModel is null)
        {
            return;
        }

        _syncing = true;
        try
        {
            if (CipherPasswordBox.Password != _boundViewModel.Password)
            {
                CipherPasswordBox.Password = _boundViewModel.Password;
            }

            if (CipherConfirmBox.Password != _boundViewModel.ConfirmPassword)
            {
                CipherConfirmBox.Password = _boundViewModel.ConfirmPassword;
            }
        }
        finally
        {
            _syncing = false;
        }
    }

    private void CipherPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || _boundViewModel is null || sender is not PasswordBox box)
        {
            return;
        }

        _syncing = true;
        try
        {
            _boundViewModel.Password = box.Password;
        }
        finally
        {
            _syncing = false;
        }
    }

    private void CipherConfirmBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || _boundViewModel is null || sender is not PasswordBox box)
        {
            return;
        }

        _syncing = true;
        try
        {
            _boundViewModel.ConfirmPassword = box.Password;
        }
        finally
        {
            _syncing = false;
        }
    }
}
