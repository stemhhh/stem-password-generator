using System.IO;
using System.Security.Cryptography;
using Microsoft.UI;
using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using StemPasswordGenerator.Helpers;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using StemPasswordGenerator.ViewModels;
using Windows.ApplicationModel.DataTransfer;
using Windows.Security.Credentials.UI;
using Windows.Storage;
using Windows.System;
using WinRT.Interop;

namespace StemPasswordGenerator.Views;

public sealed partial class MainWindow : Window
{
    private const double WheelScrollStep = 96;

    private readonly IntPtr _windowHandle;
    private readonly AppWindow _appWindow;
    private readonly PointerEventHandler _lowerSectionPointerWheelHandler;
    private readonly MainViewModel _viewModel;
    private readonly VaultViewModel _vaultViewModel;
    private readonly CipherViewModel _cipherViewModel;
    private readonly DispatcherTimer _idleTimer;
    private readonly DispatcherTimer _workAreaTimer;
    private TrayHotkeyService? _tray;
    private PointerRoutedEventArgs? _lastHandledLowerSectionWheelEvent;
    private bool _fittingWindow;
    private bool _exiting;
    private double _lastRasterizationScale;
    private DateTimeOffset _lastActivity = DateTimeOffset.UtcNow;
    private int _generateColumns = -1;

    public MainWindow()
    {
        InitializeComponent();
        Title = "Stem Password Generator";
        _lowerSectionPointerWheelHandler = OnLowerSectionPointerWheelChanged;
        _windowHandle = WindowNative.GetWindowHandle(this);
        _appWindow = AppWindow.GetFromWindowId(Win32Interop.GetWindowIdFromWindow(_windowHandle));
        ConfigureWindow();
        PasswordTextBox.Loaded += LowerSectionControl_Loaded;
        CopyButton.Loaded += LowerSectionControl_Loaded;
        StrengthSection.Loaded += LowerSectionControl_Loaded;
        AppTitleBar.Loaded += AppTitleBar_Loaded;
        Root.Loaded += Root_Loaded;

        var clipboard = new ClipboardService();
        Root.DataContext = new MainViewModel(
            new SecretGenerator(),
            new PasswordStrengthService(),
            new UserPreferencesService(),
            clipboard);
        _viewModel = (MainViewModel)Root.DataContext;
        _vaultViewModel = new VaultViewModel(new VaultStore(), clipboard);
        _cipherViewModel = new CipherViewModel(clipboard);
        VaultHost.DataContext = _vaultViewModel;
        CheckHost.DataContext = _viewModel;
        CipherHost.DataContext = _cipherViewModel;
        ProtectHost.DataContext = _vaultViewModel;
        UsbHost.DataContext = _vaultViewModel;
        SettingsHost.DataContext = _viewModel;
        _vaultViewModel.AskSharePasswordAsync = AskSharePasswordAsync;
        _vaultViewModel.AskLabeledPasswordAsync = AskLabeledPasswordAsync;
        _vaultViewModel.SaveShamirCardsAsync = SaveShamirCardsAsync;
        _vaultViewModel.PickTextFilesAsync = PickTextFilesAsync;
        _vaultViewModel.ConfirmAsync = ConfirmAsync;
        _vaultViewModel.ShowRecoveryKitAsync = ShowRecoveryKitAsync;
        _vaultViewModel.AskRecoverySecretAsync = AskRecoverySecretAsync;
        _vaultViewModel.AskNewMasterAsync = AskNewMasterAsync;
        _viewModel.InspectVault = _vaultViewModel.InspectGeneratedSecret;
        _viewModel.RefreshStudentWhy();
        _vaultViewModel.PanicCompleted = ShowVaultPage;
        _vaultViewModel.VaultPageRequested = ShowVaultPage;
        _vaultViewModel.FactoryResetCompleted = OnFactoryResetCompleted;
        _viewModel.ResetAppDataRequested = () => _vaultViewModel.ResetAppDataAsync();
        _vaultViewModel.PickFileRequested = PickFileAsync;
        _vaultViewModel.PickMediaRequested = PickMediaAsync;
        _vaultViewModel.SaveMediaRequested = SaveMediaAsync;
        _vaultViewModel.SaveFileRequested = SaveFileAsync;
        _vaultViewModel.AutofillRequested = OnAutofillRequested;
        _vaultViewModel.ComposeRequested = OnComposeRequested;
        _viewModel.PropertyChanged += OnViewModelPropertyChanged;
        _viewModel.SaveToVaultRequested += OnSaveToVaultRequested;
        ShellNav.SelectedItem = GenerateNavItem;
        Root.ActualThemeChanged += OnRootActualThemeChanged;
        ApplyTheme(_viewModel.Theme);
        PasswordTextBox.DoubleTapped += PasswordTextBox_DoubleTapped;
        Activated += OnWindowActivated;
        Closed += OnWindowClosed;
        Root.PointerPressed += (_, _) => NoteActivity();
        Root.PointerMoved += (_, _) => NoteActivityThrottled();
        Root.AddHandler(UIElement.KeyDownEvent, new KeyEventHandler(OnRootKeyDown), true);
        Microsoft.Win32.SystemEvents.SessionSwitch += OnSessionSwitch;
        _idleTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _idleTimer.Tick += OnIdleTimerTick;
        _workAreaTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(120) };
        _workAreaTimer.Tick += OnWorkAreaTimerTick;
        _vaultViewModel.PropertyChanged += OnVaultPropertyChanged;
        UiStrings.LanguageChanged += OnLanguageChanged;
        ApplyChromeLanguage();
        ApplyVaultLockBadge();
        _tray = new TrayHotkeyService(DispatcherQueue);
        _tray.OpenRequested += BringToFront;
        _tray.GenerateRequested += OnTrayGenerate;
        _tray.FillRequested += OnTrayFill;
        _tray.PanicRequested += OnTrayPanic;
        _tray.ExitRequested += QuitFromTray;
        ApplyTrayPreferences();
        _appWindow.Closing += OnAppWindowClosing;
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        DispatcherQueue.TryEnqueue(ApplyChromeLanguage);
    }

    private void ApplyChromeLanguage()
    {
        Title = UiStrings.Get("AppTitle");
        AppTitleBar.Title = UiStrings.Get("AppTitle");
        AppTitleBar.Subtitle = UiStrings.Get("AppSubtitle");
        GenerateNavItem.Content = UiStrings.Get("NavGenerate");
        CheckNavItem.Content = UiStrings.Get("NavCheck");
        CipherNavItem.Content = UiStrings.Get("NavCipher");
        VaultNavItem.Content = UiStrings.Get("NavVault");
        VaultItemsNavItem.Content = UiStrings.Get("NavVaultItems");
        VaultMediaNavItem.Content = UiStrings.Get("NavVaultMedia");
        VaultMediaPhotosNavItem.Content = UiStrings.Get("MediaGalleryPhotos");
        VaultMediaVideosNavItem.Content = UiStrings.Get("MediaGalleryVideos");
        VaultMediaAudioNavItem.Content = UiStrings.Get("MediaGalleryAudio");
        VaultMediaFilesNavItem.Content = UiStrings.Get("MediaGalleryFiles");
        VaultActivityNavItem.Content = UiStrings.Get("NavVaultActivity");
        ProtectNavItem.Content = UiStrings.Get("NavProtect");
        UsbNavItem.Content = UiStrings.Get("NavUsb");
        SettingsNavItem.Content = UiStrings.Get("NavSettings");
        AboutNavItem.Content = UiStrings.Get("NavAbout");
        ApplyVaultLockBadge();
        _tray?.UpdateTooltip();
    }

    private void OnViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.Theme))
        {
            ApplyTheme(_viewModel.Theme);
        }
        else if (e.PropertyName is nameof(MainViewModel.StayInTray) or nameof(MainViewModel.GlobalHotkeys))
        {
            ApplyTrayPreferences();
        }
        else if (e.PropertyName == nameof(MainViewModel.Password) && PasswordTextBox.IsLoaded)
        {
            PasswordTextBox.SelectAll();
        }
    }

    private void ApplyTheme(AppTheme theme)
    {
        ThemeBrushCache.Clear();
        Root.RequestedTheme = theme switch
        {
            AppTheme.Light => ElementTheme.Light,
            AppTheme.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default
        };
        _viewModel.NotifyThemeResources();
    }

    private void PasswordTextBox_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        _viewModel.CopyPasswordCommand.Execute(null);
    }

    private void ConfigureWindow()
    {
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        if (_appWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.PreferredMinimumWidth = (int)WindowPlacement.MinimumWidthDip;
            presenter.PreferredMinimumHeight = (int)WindowPlacement.MinimumHeightDip;
            presenter.IsResizable = true;
            presenter.IsMinimizable = true;
            presenter.IsMaximizable = true;
        }

        var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico");
        if (File.Exists(iconPath))
        {
            _appWindow.SetIcon(iconPath);
        }

        _lastRasterizationScale = WindowPlacement.GetScale(_windowHandle);
        ApplyInitialPlacement(_lastRasterizationScale);
        RuntimeHardening.ProtectWindowFromCapture(_windowHandle);
    }

    private void ApplyInitialPlacement(double? scale = null)
    {
        var displayArea = DisplayArea.GetFromWindowId(_appWindow.Id, DisplayAreaFallback.Nearest);
        _fittingWindow = true;
        try
        {
            _appWindow.MoveAndResize(WindowPlacement.FitInitial(_windowHandle, displayArea, scale));
        }
        finally
        {
            _fittingWindow = false;
        }
    }

    private void Root_Loaded(object sender, RoutedEventArgs e)
    {
        Root.Loaded -= Root_Loaded;
        if (Root.XamlRoot is null)
        {
            return;
        }

        var scale = Root.XamlRoot.RasterizationScale;
        if (Math.Abs(scale - _lastRasterizationScale) >= 0.01)
        {
            ApplyInitialPlacement(scale);
        }

        _lastRasterizationScale = scale;
        Root.XamlRoot.Changed += OnXamlRootChanged;
        _appWindow.Changed += OnAppWindowChanged;
        _ = _vaultViewModel.InitializeAsync();
    }

    private void OnXamlRootChanged(XamlRoot sender, XamlRootChangedEventArgs args)
    {
        var scale = sender.RasterizationScale;
        if (Math.Abs(scale - _lastRasterizationScale) < 0.01)
        {
            return;
        }

        var previous = _lastRasterizationScale;
        _lastRasterizationScale = scale;
        ApplyDpiScale(previous, scale);
    }

    private void OnAppWindowChanged(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (_fittingWindow || (!args.DidPositionChange && !args.DidSizeChange && !args.DidPresenterChange))
        {
            return;
        }

        if (_viewModel.AutoLockVault
            && _vaultViewModel.IsUnlocked
            && !_vaultViewModel.IsPanicDecoySession
            && _appWindow.Presenter is OverlappedPresenter presenter
            && presenter.State == OverlappedPresenterState.Minimized)
        {
            _vaultViewModel.Lock("LockedMinimized");
            return;
        }

        QueueKeepWindowInsideWorkArea();
    }

    private void OnVaultPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if ((e.PropertyName == nameof(VaultViewModel.IsMediaSection)
                || e.PropertyName == nameof(VaultViewModel.IsAuditSection)
                || e.PropertyName == nameof(VaultViewModel.MediaGalleryCategory))
            && VaultHost.Visibility == Visibility.Visible)
        {
            var target = _vaultViewModel.IsAuditSection
                ? VaultActivityNavItem
                : _vaultViewModel.IsMediaSection ? MediaNavItemFor(_vaultViewModel.MediaGalleryCategory) : VaultItemsNavItem;
            if (!ReferenceEquals(ShellNav.SelectedItem, target))
            {
                ShellNav.SelectedItem = target;
            }
        }

        if (e.PropertyName != nameof(VaultViewModel.IsUnlocked))
        {
            return;
        }

        ApplyVaultLockBadge();
        if (_vaultViewModel.IsUnlocked)
        {
            NoteActivity();
            _idleTimer.Start();
        }
        else
        {
            _idleTimer.Stop();
            _viewModel.SetStudentSiteUrl(null);
        }

        _viewModel.RefreshStudentWhy();
        _viewModel.RefreshCheck();
    }

    private void ApplyVaultLockBadge()
    {
        var unlocked = _vaultViewModel.IsUnlocked;
        var label = UiStrings.Get(unlocked ? "VaultStatusUnlocked" : "VaultStatusLocked");
        var hint = UiStrings.Get(unlocked ? "VaultStatusUnlockedHint" : "VaultStatusLockedHint");
        var brush = ThemeBrush(unlocked ? "SystemFillColorSuccessBrush" : "SystemFillColorCriticalBrush");

        VaultLockBadgeLabel.Text = label;
        VaultLockBadgeIcon.Glyph = unlocked ? "\uE785" : "\uE72E";
        VaultLockBadgeIcon.Foreground = brush;
        VaultLockBadgeLabel.Foreground = brush;
        VaultLockBadgeDot.Fill = brush;
        VaultLockBadge.BorderBrush = brush;
        ToolTipService.SetToolTip(VaultLockBadge, hint);
        AutomationProperties.SetName(VaultLockBadge, hint);
    }

    private static Brush ThemeBrush(string key)
    {
        var cached = ThemeBrushCache.Get(key);
        if (cached is Brush brush)
        {
            return brush;
        }

        return new SolidColorBrush(key.Contains("Success", StringComparison.Ordinal)
            ? Windows.UI.Color.FromArgb(255, 16, 124, 16)
            : Windows.UI.Color.FromArgb(255, 196, 43, 28));
    }

    private void VaultLockBadge_Click(object sender, RoutedEventArgs e) => ShowVaultPage();

    private void NoteActivity()
    {
        _lastActivity = DateTimeOffset.UtcNow;
    }

    private void NoteActivityThrottled()
    {
        if (DateTimeOffset.UtcNow - _lastActivity < TimeSpan.FromSeconds(1))
        {
            return;
        }

        NoteActivity();
    }

    private void OnIdleTimerTick(object? sender, object e)
    {
        if (!_viewModel.AutoLockVault || !_vaultViewModel.IsUnlocked || _vaultViewModel.IsPanicDecoySession)
        {
            return;
        }

        if (DateTimeOffset.UtcNow - _lastActivity < TimeSpan.FromMinutes(2))
        {
            return;
        }

        _vaultViewModel.Lock("LockedIdle");
    }

    private void OnWindowActivated(object sender, WindowActivatedEventArgs args)
    {
        if (args.WindowActivationState != WindowActivationState.Deactivated)
        {
            NoteActivity();
        }
    }

    private void OnWindowClosed(object sender, WindowEventArgs args)
    {
        _idleTimer.Stop();
        _idleTimer.Tick -= OnIdleTimerTick;
        _workAreaTimer.Stop();
        _workAreaTimer.Tick -= OnWorkAreaTimerTick;
        Root.ActualThemeChanged -= OnRootActualThemeChanged;
        _vaultViewModel.PropertyChanged -= OnVaultPropertyChanged;
        UiStrings.LanguageChanged -= OnLanguageChanged;
        Microsoft.Win32.SystemEvents.SessionSwitch -= OnSessionSwitch;
        _appWindow.Closing -= OnAppWindowClosing;
        _tray?.Dispose();
        _tray = null;
        _viewModel.FlushPreferences();
        _vaultViewModel.Lock();
    }

    private void OnSessionSwitch(object sender, Microsoft.Win32.SessionSwitchEventArgs e)
    {
        if (e.Reason is Microsoft.Win32.SessionSwitchReason.SessionLock or Microsoft.Win32.SessionSwitchReason.SessionLogoff)
        {
            DispatcherQueue.TryEnqueue(() => _vaultViewModel.Lock("LockedWindows"));
        }
    }

    private void OnRootActualThemeChanged(FrameworkElement sender, object args)
    {
        ThemeBrushCache.Clear();
        _viewModel.NotifyThemeResources();
        ApplyVaultLockBadge();
    }

    private void OnWorkAreaTimerTick(object? sender, object e)
    {
        _workAreaTimer.Stop();
        KeepWindowInsideWorkArea();
    }

    private void QueueKeepWindowInsideWorkArea()
    {
        _workAreaTimer.Stop();
        _workAreaTimer.Start();
    }

    private void ApplyDpiScale(double fromScale, double toScale)
    {
        if (_appWindow.Presenter is OverlappedPresenter presenter
            && presenter.State is OverlappedPresenterState.Maximized or OverlappedPresenterState.Minimized)
        {
            return;
        }

        var displayArea = DisplayArea.GetFromWindowId(_appWindow.Id, DisplayAreaFallback.Nearest);
        _fittingWindow = true;
        try
        {
            _appWindow.MoveAndResize(WindowPlacement.ScaleKeepingOrigin(_appWindow, displayArea, fromScale, toScale));
        }
        finally
        {
            _fittingWindow = false;
        }
    }

    private void ContentRoot_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (Math.Abs(e.NewSize.Width - e.PreviousSize.Width) < 0.5)
        {
            return;
        }

        ApplyGenerateLayout(e.NewSize.Width);
        var pane = FluidLayout.NavigationPaneLength(Bounds.Width);
        if (Math.Abs(ShellNav.OpenPaneLength - pane) > 0.5)
        {
            ShellNav.OpenPaneLength = pane;
        }
    }

    private void ApplyGenerateLayout(double width)
    {
        var padding = FluidLayout.PagePadding(width);
        var thickness = new Thickness(padding.Left, padding.Top, padding.Right, padding.Bottom);
        if (Math.Abs(ContentRoot.Padding.Left - thickness.Left) > 0.5
            || Math.Abs(ContentRoot.Padding.Top - thickness.Top) > 0.5
            || Math.Abs(ContentRoot.Padding.Right - thickness.Right) > 0.5
            || Math.Abs(ContentRoot.Padding.Bottom - thickness.Bottom) > 0.5)
        {
            ContentRoot.Padding = thickness;
        }

        var gutter = FluidLayout.Gutter(width);
        if (Math.Abs(ContentRoot.ColumnSpacing - gutter) > 0.5)
        {
            ContentRoot.ColumnSpacing = gutter;
            ContentRoot.RowSpacing = gutter;
        }

        var columns = FluidLayout.GenerateColumns(width);
        HistoryList.MaxHeight = FluidLayout.HistoryMaxHeight(columns);
        if (columns == _generateColumns)
        {
            return;
        }

        _generateColumns = columns;
        if (columns == 1)
        {
            PlaceGenerate(OutputSection, 0, 0, 3, 1);
            PlaceGenerate(OptionsSection, 0, 1, 3, 1);
            PlaceGenerate(HistorySection, 0, 2, 3, 1);
        }
        else if (columns == 2)
        {
            PlaceGenerate(OutputSection, 0, 0, 2, 2);
            PlaceGenerate(OptionsSection, 2, 0, 1, 1);
            PlaceGenerate(HistorySection, 2, 1, 1, 1);
        }
        else
        {
            PlaceGenerate(OutputSection, 0, 0, 1, 1);
            PlaceGenerate(OptionsSection, 1, 0, 1, 1);
            PlaceGenerate(HistorySection, 2, 0, 1, 1);
        }
    }

    private static void PlaceGenerate(FrameworkElement element, int column, int row, int columnSpan, int rowSpan)
    {
        Grid.SetColumn(element, column);
        Grid.SetRow(element, row);
        Grid.SetColumnSpan(element, columnSpan);
        Grid.SetRowSpan(element, rowSpan);
    }

    private void KeepWindowInsideWorkArea()
    {
        if (_appWindow.Presenter is OverlappedPresenter presenter
            && presenter.State is OverlappedPresenterState.Maximized or OverlappedPresenterState.Minimized)
        {
            return;
        }

        var displayArea = DisplayArea.GetFromWindowId(_appWindow.Id, DisplayAreaFallback.Nearest);
        var fitted = WindowPlacement.FitIfOutside(_appWindow, displayArea);
        if (fitted is null)
        {
            return;
        }

        _fittingWindow = true;
        try
        {
            _appWindow.MoveAndResize(fitted.Value);
        }
        finally
        {
            _fittingWindow = false;
        }
    }

    private void AppTitleBar_Loaded(object sender, RoutedEventArgs e)
    {
        VisualStateManager.GoToState(AppTitleBar, "SubtitleTextVisible", false);
        AppTitleBar.InvalidateMeasure();
    }

    private void LowerSectionControl_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is not UIElement element)
        {
            return;
        }

        element.AddHandler(
            UIElement.PointerWheelChangedEvent,
            _lowerSectionPointerWheelHandler,
            true);

        if (PasswordTextBox.IsLoaded && CopyButton.IsLoaded && StrengthSection.IsLoaded)
        {
            PasswordTextBox.Loaded -= LowerSectionControl_Loaded;
            CopyButton.Loaded -= LowerSectionControl_Loaded;
            StrengthSection.Loaded -= LowerSectionControl_Loaded;
        }
    }

    private void OnLowerSectionPointerWheelChanged(object sender, PointerRoutedEventArgs e)
    {
        if (ReferenceEquals(_lastHandledLowerSectionWheelEvent, e))
        {
            return;
        }

        if (MainScrollViewer.ScrollableHeight <= 0 || sender is not UIElement sourceElement)
        {
            return;
        }

        var delta = e.GetCurrentPoint(sourceElement).Properties.MouseWheelDelta;
        if (delta == 0)
        {
            return;
        }

        var targetOffset = Math.Clamp(
            MainScrollViewer.VerticalOffset - Math.Sign(delta) * WheelScrollStep,
            0,
            MainScrollViewer.ScrollableHeight);

        if (Math.Abs(targetOffset - MainScrollViewer.VerticalOffset) < 0.1)
        {
            return;
        }

        var changed = MainScrollViewer.ChangeView(null, targetOffset, null, false);
        if (changed)
        {
            e.Handled = true;
            _lastHandledLowerSectionWheelEvent = e;
        }
    }

    private void ShellNav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        var tag = (args.SelectedItem as NavigationViewItem)?.Tag as string ?? "generate";
        var mediaPage = tag is "vault-media" or "vault-media-photo" or "vault-media-video" or "vault-media-audio" or "vault-media-file";
        var vaultPage = tag is "vault" or "vault-activity" || mediaPage;
        MainScrollViewer.Visibility = tag == "generate" ? Visibility.Visible : Visibility.Collapsed;
        VaultHost.Visibility = vaultPage ? Visibility.Visible : Visibility.Collapsed;
        CheckHost.Visibility = tag == "check" ? Visibility.Visible : Visibility.Collapsed;
        CipherHost.Visibility = tag == "cipher" ? Visibility.Visible : Visibility.Collapsed;
        ProtectHost.Visibility = tag == "protect" ? Visibility.Visible : Visibility.Collapsed;
        UsbHost.Visibility = tag == "usb" ? Visibility.Visible : Visibility.Collapsed;
        SettingsHost.Visibility = tag == "settings" ? Visibility.Visible : Visibility.Collapsed;
        AboutHost.Visibility = tag == "about" ? Visibility.Visible : Visibility.Collapsed;
        if (vaultPage)
        {
            if (!_vaultViewModel.IsUnlocked)
            {
                _vaultViewModel.IsAuditSection = false;
                _vaultViewModel.IsMediaSection = false;
            }
            else if (tag == "vault-activity")
            {
                _vaultViewModel.IsAuditSection = true;
            }
            else if (mediaPage)
            {
                _vaultViewModel.OpenMediaGallery(tag switch
                {
                    "vault-media-video" => MediaCategory.Video,
                    "vault-media-audio" => MediaCategory.Audio,
                    "vault-media-file" => MediaCategory.File,
                    _ => MediaCategory.Photo
                });
            }
            else
            {
                _vaultViewModel.IsAuditSection = false;
                _vaultViewModel.IsMediaSection = false;
            }
        }
    }

    private void OnFactoryResetCompleted()
    {
        _viewModel.ResetSessionAfterAppErase();
        _cipherViewModel.ResetSession();
        ApplyTrayPreferences();
        ApplyTheme(_viewModel.Theme);
        ShowVaultPage();
    }

    private void ShowVaultPage()
    {
        ShellNav.SelectedItem = _vaultViewModel.IsAuditSection
            ? VaultActivityNavItem
            : _vaultViewModel.IsMediaSection ? MediaNavItemFor(_vaultViewModel.MediaGalleryCategory) : VaultItemsNavItem;
    }

    private NavigationViewItem MediaNavItemFor(string category) => category switch
    {
        MediaCategory.Video => VaultMediaVideosNavItem,
        MediaCategory.Audio => VaultMediaAudioNavItem,
        MediaCategory.File => VaultMediaFilesNavItem,
        _ => VaultMediaPhotosNavItem
    };

    public void BringToFront()
    {
        if (!_appWindow.IsVisible)
        {
            _appWindow.Show();
        }

        Activate();
        RuntimeHardening.ProtectWindowFromCapture(_windowHandle);
        NoteActivity();
    }

    private void HideToTray()
    {
        if (_appWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.Minimize();
            return;
        }

        _appWindow.Hide();
    }

    private void Root_DragOver(object sender, DragEventArgs e)
    {
        var canDrop = e.DataView.Contains(StandardDataFormats.StorageItems);
        e.AcceptedOperation = canDrop ? DataPackageOperation.Copy : DataPackageOperation.None;
        DropOverlay.Visibility = canDrop ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Root_DragLeave(object sender, DragEventArgs e)
    {
        DropOverlay.Visibility = Visibility.Collapsed;
    }

    private async void Root_Drop(object sender, DragEventArgs e)
    {
        DropOverlay.Visibility = Visibility.Collapsed;
        if (!e.DataView.Contains(StandardDataFormats.StorageItems))
        {
            return;
        }

        BringToFront();
        IReadOnlyList<IStorageItem> items;
        try
        {
            items = await e.DataView.GetStorageItemsAsync();
        }
        catch (Exception)
        {
            return;
        }

        foreach (var file in items.OfType<StorageFile>())
        {
            var buffer = await FileIO.ReadBufferAsync(file);
            var data = new byte[buffer.Length];
            Windows.Storage.Streams.DataReader.FromBuffer(buffer).ReadBytes(data);
            await _vaultViewModel.SealDroppedFileAsync(file.Name, data);
        }
    }

    private void ApplyTrayPreferences()
    {
        if (_tray is null)
        {
            return;
        }

        if (_viewModel.StayInTray)
        {
            _tray.ShowIcon();
        }
        else
        {
            _tray.HideIcon();
            if (!_appWindow.IsVisible)
            {
                BringToFront();
            }
        }

        if (_viewModel.GlobalHotkeys)
        {
            _tray.RegisterHotkeys();
        }
        else
        {
            _tray.UnregisterHotkeys();
        }
    }

    private void OnAppWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (_exiting || !_viewModel.StayInTray)
        {
            return;
        }

        args.Cancel = true;
        HideToTray();
    }

    private void OnTrayGenerate()
    {
        _viewModel.GenerateAndCopy();
        if (!string.IsNullOrEmpty(_viewModel.Password))
        {
            _tray?.ShowNotification(UiStrings.Get("TrayGeneratedCopied"));
        }
    }

    private void OnTrayFill()
    {
        if (!_vaultViewModel.IsUnlocked)
        {
            _tray?.ShowNotification(UiStrings.Get("TrayUnlockToFill"));
            BringToFront();
            ShowVaultPage();
            return;
        }

        var hint = AutofillService.GetForegroundAppHint();
        if (!_vaultViewModel.TryGetFillCredentials(hint, out var username, out var password)
            || !AutofillService.TryFill(username, password))
        {
            _tray?.ShowNotification(UiStrings.Get("TrayFillFailed"));
        }
    }

    private void OnTrayPanic()
    {
        _viewModel.ClearCheckSecret();
        _ = _vaultViewModel.PanicLockAsync();
    }

    private void QuitFromTray()
    {
        _exiting = true;
        Close();
    }

    private void OnRootKeyDown(object sender, KeyRoutedEventArgs e)
    {
        NoteActivity();
        if (e.Key != VirtualKey.L)
        {
            return;
        }

        var control = InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Control);
        var shift = InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Shift);
        if (!control.HasFlag(Windows.UI.Core.CoreVirtualKeyStates.Down) || !shift.HasFlag(Windows.UI.Core.CoreVirtualKeyStates.Down))
        {
            return;
        }

        RunPanicLockShortcut();
        e.Handled = true;
    }

    private void RunPanicLockShortcut()
    {
        _viewModel.ClearCheckSecret();
        _vaultViewModel.PanicLockCommand.Execute(null);
    }

    private async void OnSaveToVaultRequested(object? sender, EventArgs e)
    {
        var titleBox = new TextBox
        {
            Header = UiStrings.Get("Name"),
            PlaceholderText = UiStrings.Get("NamePlaceholder")
        };
        var urlBox = new TextBox
        {
            Header = UiStrings.Get("WebsiteOrApp"),
            PlaceholderText = UiStrings.Get("WebsitePlaceholder")
        };
        var userBox = new TextBox
        {
            Header = UiStrings.Get("UsernameOrEmail")
        };

        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = UiStrings.Get("SaveToVault"),
            PrimaryButtonText = _vaultViewModel.IsUnlocked ? UiStrings.Get("Save") : UiStrings.Get("Continue"),
            CloseButtonText = UiStrings.Get("Cancel"),
            DefaultButton = ContentDialogButton.Primary,
            Content = new StackPanel
            {
                Spacing = 12,
                MaxWidth = 420,
                Children =
                {
                    new TextBlock
                    {
                        Text = UiStrings.Get("SaveGeneratedHint"),
                        TextWrapping = TextWrapping.Wrap,
                        Style = (Style)Application.Current.Resources["SecondaryTextStyle"]
                    },
                    titleBox,
                    urlBox,
                    userBox
                }
            }
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        var title = titleBox.Text;
        var url = urlBox.Text;
        var username = userBox.Text;

        if (_vaultViewModel.IsUnlocked)
        {
            await _vaultViewModel.SaveGeneratedAsync(_viewModel.Password, title, url, username);
            _viewModel.SetStudentSiteUrl(url);
            ShowVaultPage();
            return;
        }

        _vaultViewModel.QueueGeneratedLogin(_viewModel.Password, title, url, username);
        _viewModel.SetStudentSiteUrl(url);
        ShowVaultPage();
    }

    private async Task<string?> AskSharePasswordAsync(string title)
    {
        var passwordBox = new PasswordBox
        {
            Header = UiStrings.Get("SharePasswordHeader"),
            PasswordRevealMode = PasswordRevealMode.Peek
        };
        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = title,
            PrimaryButtonText = UiStrings.Get("Continue"),
            CloseButtonText = UiStrings.Get("Cancel"),
            DefaultButton = ContentDialogButton.Primary,
            Content = new StackPanel
            {
                Spacing = 12,
                MaxWidth = 400,
                Children =
                {
                    new TextBlock
                    {
                        Text = UiStrings.Get("SharePasswordHint"),
                        TextWrapping = TextWrapping.Wrap,
                        Style = (Style)Application.Current.Resources["SecondaryTextStyle"]
                    },
                    passwordBox
                }
            }
        };

        return await dialog.ShowAsync() == ContentDialogResult.Primary ? passwordBox.Password : null;
    }

    private async Task<string?> AskLabeledPasswordAsync(string title, string header, string hint)
    {
        var passwordBox = new PasswordBox
        {
            Header = header,
            PasswordRevealMode = PasswordRevealMode.Peek
        };
        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = title,
            PrimaryButtonText = UiStrings.Get("Continue"),
            CloseButtonText = UiStrings.Get("Cancel"),
            DefaultButton = ContentDialogButton.Close,
            Content = new StackPanel
            {
                Spacing = 12,
                MaxWidth = 400,
                Children =
                {
                    new TextBlock
                    {
                        Text = hint,
                        TextWrapping = TextWrapping.Wrap,
                        Style = (Style)Application.Current.Resources["SecondaryTextStyle"]
                    },
                    passwordBox
                }
            }
        };

        return await dialog.ShowAsync() == ContentDialogResult.Primary ? passwordBox.Password : null;
    }

    private async Task<bool> SaveShamirCardsAsync(IReadOnlyList<ShamirCard> cards)
    {
        var picker = new Windows.Storage.Pickers.FolderPicker();
        InitializeWithWindow.Initialize(picker, _windowHandle);
        picker.SuggestedStartLocation = Windows.Storage.Pickers.PickerLocationId.DocumentsLibrary;
        picker.FileTypeFilter.Add("*");
        var folder = await picker.PickSingleFolderAsync();
        if (folder is null)
        {
            return false;
        }

        foreach (var card in cards)
        {
            var file = await folder.CreateFileAsync(card.FileName, CreationCollisionOption.GenerateUniqueName);
            await FileIO.WriteTextAsync(file, card.Body);
        }

        return true;
    }

    private async Task<IReadOnlyList<string>?> PickTextFilesAsync()
    {
        var picker = new Windows.Storage.Pickers.FileOpenPicker();
        InitializeWithWindow.Initialize(picker, _windowHandle);
        picker.FileTypeFilter.Add(".txt");
        picker.FileTypeFilter.Add("*");
        var files = await picker.PickMultipleFilesAsync();
        if (files is null || files.Count == 0)
        {
            return null;
        }

        var texts = new List<string>(files.Count);
        foreach (var file in files)
        {
            texts.Add(await FileIO.ReadTextAsync(file));
        }

        return texts;
    }

    private async Task<(string Name, byte[] Data)?> PickFileAsync()
    {
        var picker = new Windows.Storage.Pickers.FileOpenPicker();
        InitializeWithWindow.Initialize(picker, _windowHandle);
        picker.FileTypeFilter.Add("*");
        var file = await picker.PickSingleFileAsync();
        if (file is null)
        {
            return null;
        }

        var buffer = await Windows.Storage.FileIO.ReadBufferAsync(file);
        var data = new byte[buffer.Length];
        Windows.Storage.Streams.DataReader.FromBuffer(buffer).ReadBytes(data);
        return (file.Name, data);
    }

    private async Task<(string Name, Stream Stream, long Length)?> PickMediaAsync(string category)
    {
        var picker = new Windows.Storage.Pickers.FileOpenPicker();
        InitializeWithWindow.Initialize(picker, _windowHandle);
        foreach (var filter in MediaPickerFilters(category))
        {
            picker.FileTypeFilter.Add(filter);
        }

        var file = await picker.PickSingleFileAsync();
        if (file is null)
        {
            return null;
        }

        var properties = await file.GetBasicPropertiesAsync();
        var stream = await file.OpenStreamForReadAsync();
        return (file.Name, stream, (long)properties.Size);
    }

    private async Task<bool> SaveMediaAsync(string fileName, Func<Stream, Task> write)
    {
        var picker = new Windows.Storage.Pickers.FileSavePicker();
        InitializeWithWindow.Initialize(picker, _windowHandle);
        picker.SuggestedFileName = Path.GetFileNameWithoutExtension(fileName);
        var extension = Path.GetExtension(fileName);
        if (string.IsNullOrWhiteSpace(extension))
        {
            extension = ".bin";
        }

        picker.FileTypeChoices.Add(UiStrings.Get("StemShareType"), [extension]);
        var file = await picker.PickSaveFileAsync();
        if (file is null)
        {
            return false;
        }

        await using var output = await file.OpenStreamForWriteAsync();
        await write(output);
        return true;
    }

    private static string[] MediaPickerFilters(string category) => category switch
    {
        MediaCategory.Photo => [".jpg", ".jpeg", ".png", ".webp", ".gif", ".heic", ".bmp"],
        MediaCategory.Video => [".mp4", ".mov", ".webm", ".mkv", ".avi"],
        MediaCategory.Audio => [".mp3", ".wav", ".m4a", ".flac", ".ogg", ".aac"],
        _ => ["*"]
    };

    private async Task SaveFileAsync(string fileName, byte[] data)
    {
        var picker = new Windows.Storage.Pickers.FileSavePicker();
        InitializeWithWindow.Initialize(picker, _windowHandle);
        picker.SuggestedFileName = Path.GetFileNameWithoutExtension(fileName);
        var extension = Path.GetExtension(fileName);
        if (string.IsNullOrWhiteSpace(extension))
        {
            extension = ".spgfile";
        }

        var typeLabel = extension.Equals(".spgfile", StringComparison.OrdinalIgnoreCase)
            ? UiStrings.Get("StemSealedType")
            : extension.Equals(".csv", StringComparison.OrdinalIgnoreCase)
                ? UiStrings.Get("CsvFileType")
                : extension.Equals(".spgp", StringComparison.OrdinalIgnoreCase)
                    ? UiStrings.Get("PortableFileType")
                    : UiStrings.Get("StemShareType");
        picker.FileTypeChoices.Add(typeLabel, [extension]);
        var file = await picker.PickSaveFileAsync();
        if (file is null)
        {
            return;
        }

        await Windows.Storage.FileIO.WriteBytesAsync(file, data);
    }

    private async Task<bool> ShowRecoveryKitAsync(RecoveryMaterials materials)
    {
        var phraseBox = new TextBox
        {
            Header = UiStrings.Get("RecoveryPhraseOnceHeader"),
            Text = VaultRecovery.FormatNumberedPhrase(materials.Phrase),
            IsReadOnly = true,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            FontSize = 20,
            FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Cascadia Mono, Consolas, Segoe UI")
        };
        var confirmBox = new TextBox
        {
            Header = UiStrings.Get("RecoveryPhraseConfirmHeader"),
            PlaceholderText = UiStrings.Get("RecoveryPhraseConfirmHint"),
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap
        };
        var mismatch = new TextBlock
        {
            Text = string.Empty,
            TextWrapping = TextWrapping.Wrap,
            Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Colors.OrangeRed)
        };
        var keyBox = new TextBox
        {
            Header = UiStrings.Get("RecoveryKeyHeader"),
            Text = materials.Key,
            IsReadOnly = true,
            TextWrapping = TextWrapping.Wrap
        };
        var exportMode = new ComboBox
        {
            Header = UiStrings.Get("RecoveryExport"),
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        exportMode.Items.Add(UiStrings.Get("RecoveryExportHello"));
        exportMode.Items.Add(UiStrings.Get("RecoveryExportPassword"));
        exportMode.Items.Add(UiStrings.Get("RecoveryExportPlain"));
        exportMode.SelectedIndex = 0;
        var exportButton = new Button
        {
            Content = UiStrings.Get("RecoveryExport"),
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        exportButton.Click += async (_, _) =>
        {
            try
            {
                await ExportRecoveryKitAsync(materials, exportMode.SelectedIndex).ConfigureAwait(true);
            }
            catch (Exception)
            {
                _vaultViewModel.SetStatus("RecoveryCouldNotExport");
            }
        };

        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = UiStrings.Get("RecoveryPhraseTitle"),
            PrimaryButtonText = UiStrings.Get("RecoveryPhraseConfirmed"),
            CloseButtonText = UiStrings.Get("RecoveryLaterButton"),
            DefaultButton = ContentDialogButton.Close,
            Content = new StackPanel
            {
                Spacing = 12,
                MaxWidth = 480,
                Children =
                {
                    new TextBlock
                    {
                        Text = UiStrings.Get("RecoveryPhraseOnceBody"),
                        TextWrapping = TextWrapping.Wrap,
                        Style = (Style)Application.Current.Resources["SecondaryTextStyle"]
                    },
                    phraseBox,
                    confirmBox,
                    mismatch,
                    keyBox,
                    exportMode,
                    exportButton
                }
            }
        };
        dialog.PrimaryButtonClick += (_, args) =>
        {
            if (!string.Equals(
                    VaultRecovery.NormalizePhrase(confirmBox.Text),
                    VaultRecovery.NormalizePhrase(materials.Phrase),
                    StringComparison.Ordinal))
            {
                args.Cancel = true;
                mismatch.Text = UiStrings.Get("RecoveryPhraseMismatch");
            }
        };

        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private async Task ExportRecoveryKitAsync(RecoveryMaterials materials, int mode)
    {
        byte[] data;
        var name = "stem-recovery.srx";
        if (mode == 0)
        {
            var availability = await UserConsentVerifier.CheckAvailabilityAsync();
            if (availability != UserConsentVerifierAvailability.Available)
            {
                return;
            }

            var verified = await UserConsentVerifier.RequestVerificationAsync(UiStrings.Get("RecoveryExportHello"));
            if (verified != UserConsentVerificationResult.Verified)
            {
                return;
            }

            data = _vaultViewModel.ProtectRecoveryExportWithHello(materials);
            name = "stem-recovery.srh";
        }
        else if (mode == 1)
        {
            var password = await AskLabeledPasswordAsync(
                UiStrings.Get("RecoveryExportPasswordTitle"),
                UiStrings.Get("RecoveryExportPasswordHeader"),
                UiStrings.Get("RecoveryExportPasswordHint"));
            if (password is null)
            {
                return;
            }

            data = await Task.Run(() => VaultRecovery.ProtectWithPassword(materials, password)).ConfigureAwait(true);
        }
        else
        {
            var accepted = await ConfirmAsync(
                UiStrings.Get("RecoveryExportPlainTitle"),
                UiStrings.Get("RecoveryExportPlainBody"),
                UiStrings.Get("RecoveryExportPlain"));
            if (!accepted)
            {
                return;
            }

            data = System.Text.Encoding.UTF8.GetBytes(
                VaultRecovery.FormatPrintable(materials, _vaultViewModel.CurrentPersonLabel, DateTimeOffset.Now));
            name = "stem-recovery.txt";
        }

        await SaveFileAsync(name, data).ConfigureAwait(true);
        CryptographicOperations.ZeroMemory(data);
        _vaultViewModel.SetStatus("RecoveryExported");
    }

    private async Task<string?> AskRecoverySecretAsync()
    {
        var keyBox = new PasswordBox
        {
            Header = UiStrings.Get("RecoveryKeyHeader"),
            PasswordRevealMode = PasswordRevealMode.Peek
        };
        var phraseBox = new PasswordBox
        {
            Header = UiStrings.Get("RecoveryPhraseHeader"),
            PasswordRevealMode = PasswordRevealMode.Peek
        };
        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = UiStrings.Get("RecoverySecretTitle"),
            PrimaryButtonText = UiStrings.Get("Continue"),
            CloseButtonText = UiStrings.Get("Cancel"),
            DefaultButton = ContentDialogButton.Close,
            Content = new StackPanel
            {
                Spacing = 12,
                MaxWidth = 420,
                Children =
                {
                    new TextBlock
                    {
                        Text = UiStrings.Get("RecoverySecretHint"),
                        TextWrapping = TextWrapping.Wrap,
                        Style = (Style)Application.Current.Resources["SecondaryTextStyle"]
                    },
                    keyBox,
                    phraseBox
                }
            }
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(keyBox.Password))
        {
            return keyBox.Password;
        }

        return string.IsNullOrWhiteSpace(phraseBox.Password) ? null : phraseBox.Password;
    }

    private async Task<(string Password, string Confirm)?> AskNewMasterAsync()
    {
        var passwordBox = new PasswordBox
        {
            Header = UiStrings.Get("MasterPasswordHeader"),
            PasswordRevealMode = PasswordRevealMode.Peek
        };
        var confirmBox = new PasswordBox
        {
            Header = UiStrings.Get("ConfirmMasterPassword"),
            PasswordRevealMode = PasswordRevealMode.Peek
        };
        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = UiStrings.Get("NewMasterTitle"),
            PrimaryButtonText = UiStrings.Get("Continue"),
            CloseButtonText = UiStrings.Get("Cancel"),
            DefaultButton = ContentDialogButton.Close,
            Content = new StackPanel
            {
                Spacing = 12,
                MaxWidth = 420,
                Children =
                {
                    new TextBlock
                    {
                        Text = UiStrings.Get("NewMasterHint"),
                        TextWrapping = TextWrapping.Wrap,
                        Style = (Style)Application.Current.Resources["SecondaryTextStyle"]
                    },
                    passwordBox,
                    confirmBox
                }
            }
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return null;
        }

        return (passwordBox.Password, confirmBox.Password);
    }

    private async Task<bool> ConfirmAsync(string title, string message, string? primaryButton)
    {
        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = title,
            Content = new TextBlock
            {
                Text = message,
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 520
            },
            PrimaryButtonText = string.IsNullOrWhiteSpace(primaryButton) ? UiStrings.Get("Continue") : primaryButton,
            CloseButtonText = UiStrings.Get("Cancel"),
            DefaultButton = ContentDialogButton.Close
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private async void OnAutofillRequested()
    {
        if (!_vaultViewModel.IsUnlocked)
        {
            return;
        }

        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = UiStrings.Get("Autofill"),
            PrimaryButtonText = UiStrings.Get("Fill"),
            CloseButtonText = UiStrings.Get("Cancel"),
            Content = new TextBlock
            {
                Text = UiStrings.Get("AutofillBody"),
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 420
            }
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        await Task.Delay(400);
        var (username, password) = _vaultViewModel.GetAutofillCredentials();
        if (!AutofillService.TryFill(username, password))
        {
            var failed = new ContentDialog
            {
                XamlRoot = Root.XamlRoot,
                Title = UiStrings.Get("Autofill"),
                CloseButtonText = UiStrings.Get("Close"),
                Content = UiStrings.Get("AutofillFailed")
            };
            await failed.ShowAsync();
        }
    }

    private async void OnComposeRequested(string alias)
    {
        await Windows.System.Launcher.LaunchUriAsync(
            new Uri($"mailto:?body={Uri.EscapeDataString(UiStrings.Format("MailtoFrom", alias))}"));
    }
}
