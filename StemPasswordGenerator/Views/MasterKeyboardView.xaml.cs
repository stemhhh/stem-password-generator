using System.ComponentModel;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using StemPasswordGenerator.Services;
using StemPasswordGenerator.ViewModels;

namespace StemPasswordGenerator.Views;

public sealed partial class MasterKeyboardView : UserControl
{
    private VaultViewModel? _viewModel;

    public MasterKeyboardView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        ActualThemeChanged += (_, _) => Rebuild();
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        UiStrings.LanguageChanged -= OnLanguageChanged;
        UiStrings.LanguageChanged += OnLanguageChanged;
        AttachViewModel(DataContext as VaultViewModel);
        Rebuild();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        UiStrings.LanguageChanged -= OnLanguageChanged;
        DetachViewModel();
    }

    private void OnLanguageChanged(object? sender, EventArgs e) => DispatcherQueue.TryEnqueue(Rebuild);

    private void OnDataContextChanged(FrameworkElement sender, DataContextChangedEventArgs args)
    {
        AttachViewModel(args.NewValue as VaultViewModel);
        Rebuild();
    }

    private void AttachViewModel(VaultViewModel? viewModel)
    {
        if (ReferenceEquals(_viewModel, viewModel))
        {
            return;
        }

        DetachViewModel();
        _viewModel = viewModel;
        if (_viewModel is not null)
        {
            _viewModel.PropertyChanged += OnViewModelPropertyChanged;
        }
    }

    private void DetachViewModel()
    {
        if (_viewModel is null)
        {
            return;
        }

        _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
        _viewModel = null;
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(VaultViewModel.MasterKeyboardRevision)
            or nameof(VaultViewModel.UseMasterKeyboard)
            or null)
        {
            DispatcherQueue.TryEnqueue(Rebuild);
        }
    }

    private void Rebuild()
    {
        KeyRows.Children.Clear();
        if (_viewModel is null || !_viewModel.UseMasterKeyboard)
        {
            return;
        }

        foreach (var row in _viewModel.MasterKeyboardRows)
        {
            KeyRows.Children.Add(BuildRow(row));
        }
    }

    private Grid BuildRow(MasterKeyboardRow row)
    {
        var grid = new Grid { ColumnSpacing = 6 };
        var column = 0;
        if (row.LeftSpacer > 0)
        {
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(row.LeftSpacer, GridUnitType.Star) });
            column++;
        }

        foreach (var key in row.Keys)
        {
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(key.Flex, GridUnitType.Star) });
            var button = BuildKey(key);
            Grid.SetColumn(button, column);
            grid.Children.Add(button);
            column++;
        }

        if (row.RightSpacer > 0)
        {
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(row.RightSpacer, GridUnitType.Star) });
        }

        return grid;
    }

    private Button BuildKey(MasterKeyboardKey key)
    {
        var button = new Button
        {
            Content = LabelFor(key),
            Tag = key.Id,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            VerticalAlignment = VerticalAlignment.Stretch,
            MinHeight = 48,
            Padding = new Thickness(0),
            FontSize = key.Kind is MasterKeyKind.Character ? 20 : 14,
            FontWeight = FontWeights.SemiBold,
            CornerRadius = new CornerRadius(7)
        };
        button.Click += OnKeyClick;
        if (key.Highlighted && Resources.TryGetValue("MasterShiftOnStyle", out var style) && style is Style accent)
        {
            button.Style = accent;
        }

        return button;
    }

    private static string LabelFor(MasterKeyboardKey key)
    {
        return key.Kind switch
        {
            MasterKeyKind.Space => UiStrings.Get("MasterKeyboardSpace"),
            MasterKeyKind.Backspace => "⌫",
            _ => key.Label
        };
    }

    private void OnKeyClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string id })
        {
            _viewModel?.PressMasterKey(id);
        }
    }
}
