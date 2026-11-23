using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using StemPasswordGenerator.ViewModels;

namespace StemPasswordGenerator.Views;

public sealed partial class CheckPanel : UserControl
{
    private MainViewModel? _boundViewModel;
    private bool _syncing;

    public CheckPanel()
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

        _boundViewModel = args.NewValue as MainViewModel;
        if (_boundViewModel is not null)
        {
            _boundViewModel.PropertyChanged += OnViewModelPropertyChanged;
            SyncBox();
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
        if (e.PropertyName is nameof(MainViewModel.CheckSecret))
        {
            SyncBox();
        }
    }

    private void SyncBox()
    {
        if (_syncing || _boundViewModel is null)
        {
            return;
        }

        _syncing = true;
        try
        {
            if (CheckPasswordBox.Password != _boundViewModel.CheckSecret)
            {
                CheckPasswordBox.Password = _boundViewModel.CheckSecret;
            }
        }
        finally
        {
            _syncing = false;
        }
    }

    private void CheckPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || _boundViewModel is null || sender is not PasswordBox box)
        {
            return;
        }

        _syncing = true;
        try
        {
            _boundViewModel.CheckSecret = box.Password;
        }
        finally
        {
            _syncing = false;
        }
    }
}
