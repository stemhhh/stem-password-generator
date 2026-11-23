using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;

namespace StemPasswordGenerator.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private const int MaxHistoryItems = 8;
    private const int ClipboardClearSeconds = 30;
    private const int PreferencesDebounceMs = 400;

    private readonly SecretGenerator _secretGenerator;
    private readonly PasswordStrengthService _strengthService;
    private readonly UserPreferencesService _preferencesService;
    private readonly ClipboardService _clipboardService;
    private readonly RelayCommand _copyPasswordCommand;
    private readonly RelayCommand _saveToVaultCommand;
    private CancellationTokenSource? _copyStatusCancellation;
    private CancellationTokenSource? _excludeDebounceCancellation;
    private CancellationTokenSource? _checkDebounceCancellation;
    private CancellationTokenSource? _hibpCancellation;
    private CancellationTokenSource? _preferencesDebounceCancellation;

    private GeneratorMode _mode;
    private int _passwordLength = PasswordOptions.DefaultPasswordLength;
    private int _pinLength = PasswordOptions.DefaultPinLength;
    private int _wordCount = PasswordOptions.DefaultWordCount;
    private bool _includeUppercase = true;
    private bool _includeLowercase = true;
    private bool _includeNumbers = true;
    private bool _includeSymbols = true;
    private bool _avoidAmbiguousCharacters;
    private bool _noRepeatedCharacters;
    private bool _beginWithLetter;
    private string _excludeCharacters = string.Empty;
    private string _wordSeparator = "-";
    private bool _capitalizeWords = true;
    private bool _appendDigit = true;
    private bool _clearClipboardAfterCopy = true;
    private bool _autoLockVault = true;
    private bool _stayInTray = true;
    private bool _globalHotkeys = true;
    private bool _studentMode = true;
    private AppTheme _theme;
    private AppLanguage _language;
    private string _password = string.Empty;
    private string _copyStatusMessage = string.Empty;
    private string? _copyStatusKey;
    private object[] _copyStatusArgs = [];
    private StrengthReport _report = new(PasswordStrength.Weak, 0, "0-bit entropy", "Instant", string.Empty);
    private string _studentEntropyLine = string.Empty;
    private string _studentVaultLine = string.Empty;
    private string _studentTwoFactorLine = string.Empty;
    private string _studentMasterLine = string.Empty;
    private string? _studentSiteUrl;
    private string _checkSecret = string.Empty;
    private SecretCheckReport _checkReport = SecretCheckReport.Empty;
    private string _checkVaultLine = string.Empty;
    private bool _hibpBusy;
    private string? _hibpStatusKey;
    private object[] _hibpStatusArgs = [];

    public MainViewModel(
        SecretGenerator secretGenerator,
        PasswordStrengthService strengthService,
        UserPreferencesService preferencesService,
        ClipboardService clipboardService)
    {
        _secretGenerator = secretGenerator ?? throw new ArgumentNullException(nameof(secretGenerator));
        _strengthService = strengthService ?? throw new ArgumentNullException(nameof(strengthService));
        _preferencesService = preferencesService ?? throw new ArgumentNullException(nameof(preferencesService));
        _clipboardService = clipboardService ?? throw new ArgumentNullException(nameof(clipboardService));

        var options = _preferencesService.LoadOptions();
        _mode = options.Mode;
        _passwordLength = _preferencesService.LoadPasswordLength();
        _pinLength = _preferencesService.LoadPinLength();
        _wordCount = _preferencesService.LoadWordCount();
        ApplyLoadedOptions(options);
        _theme = _preferencesService.LoadTheme();
        _language = _preferencesService.LoadLanguage();
        UiStrings.SetLanguage(_language);
        _clearClipboardAfterCopy = _preferencesService.LoadClearClipboard();
        _autoLockVault = _preferencesService.LoadAutoLockVault();
        _stayInTray = _preferencesService.LoadStayInTray();
        _globalHotkeys = _preferencesService.LoadGlobalHotkeys();
        _studentMode = _preferencesService.LoadStudentMode();
        _clipboardService.AutoClear = _clearClipboardAfterCopy;
        _clipboardService.Cleared += OnClipboardCleared;

        GeneratePasswordCommand = new RelayCommand(GenerateNow, CanGenerate);
        _copyPasswordCommand = new RelayCommand(CopyPassword, () => !string.IsNullOrEmpty(Password));
        CopyPasswordCommand = _copyPasswordCommand;
        _saveToVaultCommand = new RelayCommand(RequestSaveToVault, () => !string.IsNullOrEmpty(Password));
        SaveToVaultCommand = _saveToVaultCommand;
        ApplyPresetCommand = new RelayCommand<string>(ApplyPreset);
        ClearHistoryCommand = new RelayCommand(() => History.Clear(), () => History.Count > 0);
        ClearCheckCommand = new RelayCommand(ClearCheckSecret, () => !string.IsNullOrEmpty(CheckSecret));
        CheckHibpCommand = new RelayCommand(() => _ = CheckHibpAsync(), CanCheckHibp);
        ResetAppDataCommand = new RelayCommand(() => _ = RequestResetAppDataAsync());

        GenerateSecret();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public event EventHandler? SaveToVaultRequested;

    public Func<string, string?, StudentVaultInsight>? InspectVault { get; set; }

    public ObservableCollection<HistoryItem> History { get; } = new();

    public GeneratorMode Mode
    {
        get => _mode;
        set
        {
            if (!SetProperty(ref _mode, value))
            {
                return;
            }

            OnPropertyChanged(nameof(IsPasswordMode));
            OnPropertyChanged(nameof(IsPassphraseMode));
            OnPropertyChanged(nameof(IsPinMode));
            OnPropertyChanged(nameof(ShowCharacterOptions));
            OnPropertyChanged(nameof(ShowPassphraseOptions));
            OnPropertyChanged(nameof(Length));
            OnPropertyChanged(nameof(MinLength));
            OnPropertyChanged(nameof(MaxLength));
            OnPropertyChanged(nameof(LengthCaption));
            OnPropertyChanged(nameof(LengthHint));
            OnPropertyChanged(nameof(GenerateLabel));
            PersistAndGenerate();
            GeneratePasswordCommand.NotifyCanExecuteChanged();
        }
    }

    public bool IsPasswordMode
    {
        get => Mode == GeneratorMode.Password;
        set { if (value) Mode = GeneratorMode.Password; }
    }

    public bool IsPassphraseMode
    {
        get => Mode == GeneratorMode.Passphrase;
        set { if (value) Mode = GeneratorMode.Passphrase; }
    }

    public bool IsPinMode
    {
        get => Mode == GeneratorMode.Pin;
        set { if (value) Mode = GeneratorMode.Pin; }
    }

    public bool ShowCharacterOptions => Mode == GeneratorMode.Password;

    public bool ShowPassphraseOptions => Mode == GeneratorMode.Passphrase;

    public int Length
    {
        get => Mode switch
        {
            GeneratorMode.Pin => _pinLength,
            GeneratorMode.Passphrase => _wordCount,
            _ => _passwordLength
        };
        set
        {
            var clamped = Math.Clamp(value, MinLength, MaxLength);
            var changed = Mode switch
            {
                GeneratorMode.Pin => SetField(ref _pinLength, clamped),
                GeneratorMode.Passphrase => SetField(ref _wordCount, clamped),
                _ => SetField(ref _passwordLength, clamped)
            };

            if (changed)
            {
                OnPropertyChanged();
                DebouncePersistAndGenerate(120);
            }
        }
    }

    public int MinLength => CreateOptions().MinimumLength;

    public int MaxLength => CreateOptions().MaximumLength;

    public string LengthCaption => Mode switch
    {
        GeneratorMode.Passphrase => UiStrings.Get("LengthWords"),
        GeneratorMode.Pin => UiStrings.Get("LengthPin"),
        _ => UiStrings.Get("LengthPassword")
    };

    public string LengthHint => Mode switch
    {
        GeneratorMode.Passphrase => UiStrings.Get("HintWords"),
        GeneratorMode.Pin => UiStrings.Get("HintPin"),
        _ => UiStrings.Get("HintPassword")
    };

    public string GenerateLabel => Mode switch
    {
        GeneratorMode.Passphrase => UiStrings.Get("GeneratePassphrase"),
        GeneratorMode.Pin => UiStrings.Get("GeneratePin"),
        _ => UiStrings.Get("GeneratePassword")
    };

    public bool IncludeUppercase { get => _includeUppercase; set => SetOption(ref _includeUppercase, value); }
    public bool IncludeLowercase { get => _includeLowercase; set => SetOption(ref _includeLowercase, value); }
    public bool IncludeNumbers { get => _includeNumbers; set => SetOption(ref _includeNumbers, value); }
    public bool IncludeSymbols { get => _includeSymbols; set => SetOption(ref _includeSymbols, value); }
    public bool AvoidAmbiguousCharacters { get => _avoidAmbiguousCharacters; set => SetOption(ref _avoidAmbiguousCharacters, value); }
    public bool NoRepeatedCharacters { get => _noRepeatedCharacters; set => SetOption(ref _noRepeatedCharacters, value); }
    public bool BeginWithLetter { get => _beginWithLetter; set => SetOption(ref _beginWithLetter, value); }
    public bool CapitalizeWords { get => _capitalizeWords; set => SetOption(ref _capitalizeWords, value); }
    public bool AppendDigit { get => _appendDigit; set => SetOption(ref _appendDigit, value); }

    public string WordSeparator
    {
        get => _wordSeparator;
        set
        {
            var separator = string.IsNullOrEmpty(value) ? "-" : value[..1];
            if (SetProperty(ref _wordSeparator, separator))
            {
                PersistAndGenerate();
            }
        }
    }

    public string ExcludeCharacters
    {
        get => _excludeCharacters;
        set
        {
            if (!SetProperty(ref _excludeCharacters, value ?? string.Empty))
            {
                return;
            }

            DebouncePersistAndGenerate(280);
        }
    }

    public bool ClearClipboardAfterCopy
    {
        get => _clearClipboardAfterCopy;
        set
        {
            if (SetProperty(ref _clearClipboardAfterCopy, value))
            {
                _clipboardService.AutoClear = value;
                SaveAppearance();
            }
        }
    }

    public bool AutoLockVault
    {
        get => _autoLockVault;
        set
        {
            if (SetProperty(ref _autoLockVault, value))
            {
                SaveAppearance();
            }
        }
    }

    public bool StayInTray
    {
        get => _stayInTray;
        set
        {
            if (SetProperty(ref _stayInTray, value))
            {
                SaveTray();
            }
        }
    }

    public bool GlobalHotkeys
    {
        get => _globalHotkeys;
        set
        {
            if (SetProperty(ref _globalHotkeys, value))
            {
                SaveTray();
            }
        }
    }

    public bool StudentMode
    {
        get => _studentMode;
        set
        {
            if (SetProperty(ref _studentMode, value))
            {
                _preferencesService.SaveStudentMode(value);
                RefreshStudentWhy();
            }
        }
    }

    public AppTheme Theme
    {
        get => _theme;
        set
        {
            if (SetProperty(ref _theme, value))
            {
                OnPropertyChanged(nameof(IsSystemTheme));
                OnPropertyChanged(nameof(IsLightTheme));
                OnPropertyChanged(nameof(IsDarkTheme));
                SaveAppearance();
            }
        }
    }

    public bool IsSystemTheme { get => Theme == AppTheme.System; set { if (value) Theme = AppTheme.System; } }
    public bool IsLightTheme { get => Theme == AppTheme.Light; set { if (value) Theme = AppTheme.Light; } }
    public bool IsDarkTheme { get => Theme == AppTheme.Dark; set { if (value) Theme = AppTheme.Dark; } }

    public int LanguageIndex
    {
        get => (int)_language;
        set
        {
            if (value is not 0 and not 1)
            {
                return;
            }

            var language = value == 1 ? AppLanguage.Spanish : AppLanguage.English;
            if (_language == language)
            {
                return;
            }

            _language = language;
            UiStrings.SetLanguage(language);
            OnPropertyChanged();
            SaveAppearance();
            NotifyLanguage();
        }
    }

    public string Password
    {
        get => _password;
        private set
        {
            if (SetProperty(ref _password, value))
            {
                _copyPasswordCommand.NotifyCanExecuteChanged();
                _saveToVaultCommand.NotifyCanExecuteChanged();
                OnPropertyChanged(nameof(CharacterCountLabel));
            }
        }
    }

    public string CharacterCountLabel => Mode == GeneratorMode.Passphrase
        ? UiStrings.Format("WordCountLabel", Length)
        : UiStrings.Format("CharacterCount", Password.Length);

    public string StrengthLabel => _report.Strength switch
    {
        PasswordStrength.Excellent => UiStrings.Get("Excellent"),
        PasswordStrength.Strong => UiStrings.Get("Strong"),
        PasswordStrength.Medium => UiStrings.Get("Medium"),
        _ => UiStrings.Get("Weak")
    };

    public string StrengthDescription => _report.Description;

    public string EntropyLabel => _report.EntropyLabel;

    public string CrackTimeLabel => _report.CrackTimeLabel;

    public PasswordStrength Strength => _report.Strength;

    public string StudentEntropyLine
    {
        get => _studentEntropyLine;
        private set => SetProperty(ref _studentEntropyLine, value);
    }

    public string StudentVaultLine
    {
        get => _studentVaultLine;
        private set => SetProperty(ref _studentVaultLine, value);
    }

    public string StudentTwoFactorLine
    {
        get => _studentTwoFactorLine;
        private set => SetProperty(ref _studentTwoFactorLine, value);
    }

    public string StudentMasterLine
    {
        get => _studentMasterLine;
        private set => SetProperty(ref _studentMasterLine, value);
    }

    public string CopyStatusMessage
    {
        get => _copyStatusMessage;
        private set => SetProperty(ref _copyStatusMessage, value);
    }

    public RelayCommand GeneratePasswordCommand { get; }

    public RelayCommand ResetAppDataCommand { get; }

    public Func<Task>? ResetAppDataRequested { get; set; }

    public RelayCommand CopyPasswordCommand { get; }

    public RelayCommand SaveToVaultCommand { get; }

    public RelayCommand<string> ApplyPresetCommand { get; }

    public RelayCommand ClearHistoryCommand { get; }

    public RelayCommand ClearCheckCommand { get; }

    public RelayCommand CheckHibpCommand { get; }

    public string CheckSecret
    {
        get => _checkSecret;
        set
        {
            var next = value ?? string.Empty;
            if (next.Length > 256)
            {
                next = next[..256];
            }

            if (SetProperty(ref _checkSecret, next))
            {
                ResetHibpStatus();
                ClearCheckCommand.NotifyCanExecuteChanged();
                CheckHibpCommand.NotifyCanExecuteChanged();
                OnPropertyChanged(nameof(HasCheckSecret));
                if (next.Length == 0)
                {
                    CancelCheckDebounce();
                    RefreshCheck();
                }
                else
                {
                    DebounceCheck();
                }
            }
        }
    }

    public bool HasCheckSecret => !string.IsNullOrEmpty(CheckSecret);

    public PasswordStrength CheckStrength => _checkReport.Strength;

    public string CheckKindLabel => _checkReport.KindLabel;

    public string CheckStrengthLabel => _checkReport.Strength switch
    {
        PasswordStrength.Excellent => UiStrings.Get("Excellent"),
        PasswordStrength.Strong => UiStrings.Get("Strong"),
        PasswordStrength.Medium => UiStrings.Get("Medium"),
        _ => UiStrings.Get("Weak")
    };

    public string CheckSummary => _checkReport.Summary;

    public string CheckEntropyLabel => _checkReport.EntropyLabel;

    public string CheckCrackTimeLabel => _checkReport.CrackTimeLabel;

    public string CheckVaultLine
    {
        get => _checkVaultLine;
        private set => SetProperty(ref _checkVaultLine, value);
    }

    public bool IsCheckHibpBusy
    {
        get => _hibpBusy;
        private set
        {
            if (SetProperty(ref _hibpBusy, value))
            {
                CheckHibpCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public string CheckHibpStatus
    {
        get
        {
            if (_hibpStatusKey is null)
            {
                return UiStrings.Get("CheckHibpIdle");
            }

            return _hibpStatusArgs.Length == 0
                ? UiStrings.Get(_hibpStatusKey)
                : UiStrings.Format(_hibpStatusKey, _hibpStatusArgs);
        }
    }

    public ObservableCollection<string> CheckFindings { get; } = [];

    public ObservableCollection<string> CheckNextSteps { get; } = [];

    public IReadOnlyList<string> CheckTips =>
    [
        UiStrings.Get("CheckTip1"),
        UiStrings.Get("CheckTip2"),
        UiStrings.Get("CheckTip3"),
        UiStrings.Get("CheckTip4"),
        UiStrings.Get("CheckTip5"),
        UiStrings.Get("CheckTip6")
    ];

    public void ClearCheckSecret()
    {
        CancelCheckDebounce();
        if (_checkSecret.Length == 0)
        {
            RefreshCheck();
            return;
        }

        _checkSecret = string.Empty;
        OnPropertyChanged(nameof(CheckSecret));
        OnPropertyChanged(nameof(HasCheckSecret));
        ClearCheckCommand.NotifyCanExecuteChanged();
        ResetHibpStatus();
        RefreshCheck();
    }

    private void ApplyLoadedOptions(PasswordOptions options)
    {
        _includeUppercase = options.IncludeUppercase;
        _includeLowercase = options.IncludeLowercase;
        _includeNumbers = options.IncludeNumbers;
        _includeSymbols = options.IncludeSymbols;
        _avoidAmbiguousCharacters = options.AvoidAmbiguousCharacters;
        _noRepeatedCharacters = options.NoRepeatedCharacters;
        _beginWithLetter = options.BeginWithLetter;
        _excludeCharacters = options.ExcludeCharacters;
        _wordSeparator = options.WordSeparator;
        _capitalizeWords = options.CapitalizeWords;
        _appendDigit = options.AppendDigit;
    }

    private void GenerateNow()
    {
        CancelDebounce();
        GenerateSecret();
        SavePreferences();
    }

    private void PersistAndGenerate()
    {
        GenerateSecret();
        ScheduleSavePreferences();
    }

    public void FlushPreferences()
    {
        CancelPreferencesDebounce();
        SavePreferences();
    }

    private void ScheduleSavePreferences()
    {
        CancelPreferencesDebounce();
        _preferencesDebounceCancellation = new CancellationTokenSource();
        var token = _preferencesDebounceCancellation.Token;
        _ = SavePreferencesLaterAsync(token);
    }

    private async Task SavePreferencesLaterAsync(CancellationToken token)
    {
        try
        {
            await Task.Delay(PreferencesDebounceMs, token).ConfigureAwait(true);
            SavePreferences();
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void CancelPreferencesDebounce()
    {
        _preferencesDebounceCancellation?.Cancel();
        _preferencesDebounceCancellation?.Dispose();
        _preferencesDebounceCancellation = null;
    }

    private void GenerateSecret()
    {
        var options = CreateOptions();
        Password = CanGenerate() ? _secretGenerator.Generate(options) : string.Empty;
        UpdateStrength(options);
        Remember(Password);
    }

    private void Remember(string secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return;
        }

        if (History.Count > 0 && History[0].Secret == secret)
        {
            return;
        }

        History.Insert(0, new HistoryItem(secret, Mode, DateTime.Now, CopyHistoryItem));
        while (History.Count > MaxHistoryItems)
        {
            History.RemoveAt(History.Count - 1);
        }

        ClearHistoryCommand.NotifyCanExecuteChanged();
    }

    private void CopyHistoryItem(HistoryItem item)
    {
        Password = item.Secret;
        UpdateStrength(CreateOptions());
        CopyPassword();
    }

    public void GenerateAndCopy()
    {
        GenerateNow();
        if (!string.IsNullOrEmpty(Password))
        {
            CopyPassword();
        }
    }

    private void RequestSaveToVault()
    {
        SaveToVaultRequested?.Invoke(this, EventArgs.Empty);
    }

    private async void CopyPassword()
    {
        if (!_clipboardService.TryCopy(Password))
        {
            SetCopyStatus("CouldNotCopy");
            return;
        }

        _copyStatusCancellation?.Cancel();
        _copyStatusCancellation?.Dispose();
        _copyStatusCancellation = new CancellationTokenSource();
        var statusToken = _copyStatusCancellation.Token;

        if (ClearClipboardAfterCopy)
        {
            SetCopyStatus("CopiedClears", ClipboardClearSeconds);
        }
        else
        {
            SetCopyStatus("CopiedNoHistory");
        }

        try
        {
            await Task.Delay(TimeSpan.FromSeconds(3), statusToken);
            ClearCopyStatus();
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void OnClipboardCleared()
    {
        SetCopyStatus("ClipboardCleared");
        _ = ClearCopiedStatusLaterAsync();
    }

    private async Task ClearCopiedStatusLaterAsync()
    {
        _copyStatusCancellation?.Cancel();
        _copyStatusCancellation?.Dispose();
        _copyStatusCancellation = new CancellationTokenSource();
        var token = _copyStatusCancellation.Token;
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(2), token);
            ClearCopyStatus();
        }
        catch (OperationCanceledException)
        {
        }
    }

    private bool CanGenerate() => GeneratorPresets.CanGenerate(CreateOptions());

    private void ApplyPreset(string? name)
    {
        var preset = GeneratorPresets.TryCreate(name);
        if (preset is null)
        {
            return;
        }

        _mode = preset.Mode;
        _includeUppercase = preset.IncludeUppercase;
        _includeLowercase = preset.IncludeLowercase;
        _includeNumbers = preset.IncludeNumbers;
        _includeSymbols = preset.IncludeSymbols;
        _avoidAmbiguousCharacters = preset.AvoidAmbiguousCharacters;
        _noRepeatedCharacters = preset.NoRepeatedCharacters;
        _beginWithLetter = preset.BeginWithLetter;
        _wordSeparator = preset.WordSeparator;
        _capitalizeWords = preset.CapitalizeWords;
        _appendDigit = preset.AppendDigit;
        switch (preset.Mode)
        {
            case GeneratorMode.Passphrase:
                _wordCount = preset.Length;
                break;
            case GeneratorMode.Pin:
                _pinLength = preset.Length;
                break;
            default:
                _passwordLength = preset.Length;
                break;
        }

        RefreshOptionProperties();
        PersistAndGenerate();
        GeneratePasswordCommand.NotifyCanExecuteChanged();
    }

    private void RefreshOptionProperties()
    {
        OnPropertyChanged(nameof(IsPasswordMode));
        OnPropertyChanged(nameof(IsPassphraseMode));
        OnPropertyChanged(nameof(IsPinMode));
        OnPropertyChanged(nameof(ShowCharacterOptions));
        OnPropertyChanged(nameof(ShowPassphraseOptions));
        OnPropertyChanged(nameof(Length));
        OnPropertyChanged(nameof(MinLength));
        OnPropertyChanged(nameof(MaxLength));
        OnPropertyChanged(nameof(LengthCaption));
        OnPropertyChanged(nameof(LengthHint));
        OnPropertyChanged(nameof(GenerateLabel));
        OnPropertyChanged(nameof(IncludeUppercase));
        OnPropertyChanged(nameof(IncludeLowercase));
        OnPropertyChanged(nameof(IncludeNumbers));
        OnPropertyChanged(nameof(IncludeSymbols));
        OnPropertyChanged(nameof(AvoidAmbiguousCharacters));
        OnPropertyChanged(nameof(NoRepeatedCharacters));
        OnPropertyChanged(nameof(BeginWithLetter));
        OnPropertyChanged(nameof(WordSeparator));
        OnPropertyChanged(nameof(CapitalizeWords));
        OnPropertyChanged(nameof(AppendDigit));
        OnPropertyChanged(nameof(CharacterCountLabel));
    }

    public void NotifyLanguage()
    {
        RefreshOptionProperties();
        UpdateStrength(CreateOptions());
        RefreshHistoryLanguage();
        if (_copyStatusKey is { } copyKey)
        {
            SetCopyStatus(copyKey, _copyStatusArgs);
        }

        RefreshCheck();
        OnPropertyChanged(nameof(CheckTips));
        OnPropertyChanged(nameof(CheckHibpStatus));
    }

    private void CancelCheckDebounce()
    {
        _checkDebounceCancellation?.Cancel();
        _checkDebounceCancellation?.Dispose();
        _checkDebounceCancellation = null;
    }

    private async void DebounceCheck()
    {
        _checkDebounceCancellation?.Cancel();
        _checkDebounceCancellation?.Dispose();
        _checkDebounceCancellation = new CancellationTokenSource();
        var token = _checkDebounceCancellation.Token;

        try
        {
            await Task.Delay(140, token);
            RefreshCheck();
        }
        catch (OperationCanceledException)
        {
        }
    }

    public void NotifyThemeResources()
    {
        UpdateStrength(CreateOptions());
    }

    private void RefreshHistoryLanguage()
    {
        for (var i = 0; i < History.Count; i++)
        {
            var item = History[i];
            History[i] = new HistoryItem(item.Secret, item.Mode, item.Created, CopyHistoryItem);
        }
    }

    private void SetCopyStatus(string key, params object[] args)
    {
        _copyStatusKey = key;
        _copyStatusArgs = args;
        CopyStatusMessage = args.Length == 0 ? UiStrings.Get(key) : UiStrings.Format(key, args);
    }

    private void ClearCopyStatus()
    {
        _copyStatusKey = null;
        _copyStatusArgs = [];
        CopyStatusMessage = string.Empty;
    }

    private void SetOption(ref bool field, bool value, [CallerMemberName] string? propertyName = null)
    {
        if (SetProperty(ref field, value, propertyName))
        {
            GeneratePasswordCommand.NotifyCanExecuteChanged();
            PersistAndGenerate();
        }
    }

    private void CancelDebounce()
    {
        _excludeDebounceCancellation?.Cancel();
        _excludeDebounceCancellation?.Dispose();
        _excludeDebounceCancellation = null;
    }

    private async void DebouncePersistAndGenerate(int delayMs)
    {
        _excludeDebounceCancellation?.Cancel();
        _excludeDebounceCancellation?.Dispose();
        _excludeDebounceCancellation = new CancellationTokenSource();
        var token = _excludeDebounceCancellation.Token;

        try
        {
            await Task.Delay(delayMs, token);
            PersistAndGenerate();
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void UpdateStrength(PasswordOptions options)
    {
        _report = _strengthService.Evaluate(Password, options);
        OnPropertyChanged(nameof(StrengthLabel));
        OnPropertyChanged(nameof(StrengthDescription));
        OnPropertyChanged(nameof(EntropyLabel));
        OnPropertyChanged(nameof(CrackTimeLabel));
        OnPropertyChanged(nameof(Strength));
        RefreshStudentWhy();
    }

    public void SetStudentSiteUrl(string? url)
    {
        _studentSiteUrl = string.IsNullOrWhiteSpace(url) ? null : url.Trim();
        RefreshStudentWhy();
    }

    public void RefreshStudentWhy()
    {
        var insight = InspectVault?.Invoke(Password, _studentSiteUrl) ?? StudentVaultInsight.Locked;
        var lines = StudentModeExplainer.Explain(_report.EntropyBits, _report.Strength, insight);
        StudentEntropyLine = lines.Entropy;
        StudentVaultLine = lines.Vault;
        StudentTwoFactorLine = lines.TwoFactor;
        StudentMasterLine = lines.Master;
    }

    public void RefreshCheck()
    {
        CancelCheckDebounce();
        _checkReport = SecretCheckService.Analyze(CheckSecret);
        CheckFindings.Clear();
        foreach (var finding in _checkReport.Findings)
        {
            CheckFindings.Add(finding);
        }

        if (CheckFindings.Count == 0 && !string.IsNullOrEmpty(CheckSecret))
        {
            CheckFindings.Add(UiStrings.Get("CheckFindingNone"));
        }

        CheckNextSteps.Clear();
        foreach (var step in _checkReport.NextSteps)
        {
            CheckNextSteps.Add(step);
        }

        CheckVaultLine = string.Empty;
        if (!string.IsNullOrEmpty(CheckSecret) && InspectVault is not null)
        {
            var insight = InspectVault(CheckSecret, _studentSiteUrl);
            if (!insight.VaultUnlocked)
            {
                CheckVaultLine = UiStrings.Get("StudentVaultLocked");
            }
            else if (insight.ReusedOnTitles.Count == 1)
            {
                CheckVaultLine = UiStrings.Format("StudentVaultReusedOne", insight.ReusedOnTitles[0]);
            }
            else if (insight.ReusedOnTitles.Count == 2)
            {
                CheckVaultLine = UiStrings.Format("StudentVaultReusedTwo", insight.ReusedOnTitles[0], insight.ReusedOnTitles[1]);
            }
            else if (insight.ReusedOnTitles.Count > 2)
            {
                CheckVaultLine = UiStrings.Format("StudentVaultReusedMany", insight.ReusedOnTitles.Count);
            }
            else
            {
                CheckVaultLine = UiStrings.Get("CheckVaultNew");
            }
        }

        OnPropertyChanged(nameof(CheckStrength));
        OnPropertyChanged(nameof(CheckStrengthLabel));
        OnPropertyChanged(nameof(CheckKindLabel));
        OnPropertyChanged(nameof(CheckSummary));
        OnPropertyChanged(nameof(CheckEntropyLabel));
        OnPropertyChanged(nameof(CheckCrackTimeLabel));
        OnPropertyChanged(nameof(HasCheckSecret));
    }

    private bool CanCheckHibp() => !string.IsNullOrEmpty(CheckSecret) && !IsCheckHibpBusy;

    private void ResetHibpStatus()
    {
        _hibpCancellation?.Cancel();
        _hibpStatusKey = null;
        _hibpStatusArgs = [];
        IsCheckHibpBusy = false;
        CheckHibpCommand.NotifyCanExecuteChanged();
        OnPropertyChanged(nameof(CheckHibpStatus));
    }

    private async Task CheckHibpAsync()
    {
        if (!CanCheckHibp())
        {
            return;
        }

        var secret = CheckSecret;
        _hibpCancellation?.Cancel();
        _hibpCancellation?.Dispose();
        _hibpCancellation = new CancellationTokenSource();
        var token = _hibpCancellation.Token;
        IsCheckHibpBusy = true;
        _hibpStatusKey = "CheckHibpChecking";
        _hibpStatusArgs = [];
        OnPropertyChanged(nameof(CheckHibpStatus));
        try
        {
            var result = await HibpPwnedClient.Shared.CheckAsync(secret, token).ConfigureAwait(true);
            if (token.IsCancellationRequested)
            {
                return;
            }

            switch (result.Status)
            {
                case HibpCheckStatus.Pwned:
                    _hibpStatusKey = "CheckHibpPwned";
                    _hibpStatusArgs = [result.Count.ToString("N0")];
                    break;
                case HibpCheckStatus.NotFound:
                    _hibpStatusKey = "CheckHibpClear";
                    _hibpStatusArgs = [];
                    break;
                default:
                    _hibpStatusKey = "CheckHibpOffline";
                    _hibpStatusArgs = [];
                    break;
            }

            OnPropertyChanged(nameof(CheckHibpStatus));
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            if (!token.IsCancellationRequested)
            {
                IsCheckHibpBusy = false;
            }
        }
    }

    private PasswordOptions CreateOptions()
    {
        return new PasswordOptions(
            Mode,
            Length,
            IncludeUppercase,
            IncludeLowercase,
            IncludeNumbers,
            IncludeSymbols,
            AvoidAmbiguousCharacters,
            NoRepeatedCharacters,
            BeginWithLetter,
            ExcludeCharacters,
            WordSeparator,
            CapitalizeWords,
            AppendDigit).Normalize();
    }

    public void ResetSessionAfterAppErase()
    {
        History.Clear();
        ClearCheckSecret();
        Password = string.Empty;
        CancelPreferencesDebounce();
        _theme = _preferencesService.LoadTheme();
        _language = _preferencesService.LoadLanguage();
        UiStrings.SetLanguage(_language);
        _clearClipboardAfterCopy = _preferencesService.LoadClearClipboard();
        _autoLockVault = _preferencesService.LoadAutoLockVault();
        _studentMode = _preferencesService.LoadStudentMode();
        _stayInTray = _preferencesService.LoadStayInTray();
        _globalHotkeys = _preferencesService.LoadGlobalHotkeys();
        var options = _preferencesService.LoadOptions();
        _mode = options.Mode;
        _passwordLength = _preferencesService.LoadPasswordLength();
        _pinLength = _preferencesService.LoadPinLength();
        _wordCount = _preferencesService.LoadWordCount();
        _includeUppercase = options.IncludeUppercase;
        _includeLowercase = options.IncludeLowercase;
        _includeNumbers = options.IncludeNumbers;
        _includeSymbols = options.IncludeSymbols;
        _avoidAmbiguousCharacters = options.AvoidAmbiguousCharacters;
        _noRepeatedCharacters = options.NoRepeatedCharacters;
        _beginWithLetter = options.BeginWithLetter;
        _excludeCharacters = options.ExcludeCharacters;
        _wordSeparator = options.WordSeparator;
        _capitalizeWords = options.CapitalizeWords;
        _appendDigit = options.AppendDigit;
        _clipboardService.AutoClear = _clearClipboardAfterCopy;
        OnPropertyChanged(nameof(Theme));
        OnPropertyChanged(nameof(IsSystemTheme));
        OnPropertyChanged(nameof(IsLightTheme));
        OnPropertyChanged(nameof(IsDarkTheme));
        OnPropertyChanged(nameof(ClearClipboardAfterCopy));
        OnPropertyChanged(nameof(AutoLockVault));
        OnPropertyChanged(nameof(StudentMode));
        OnPropertyChanged(nameof(StayInTray));
        OnPropertyChanged(nameof(GlobalHotkeys));
        OnPropertyChanged(nameof(LanguageIndex));
        OnPropertyChanged(nameof(Mode));
        RefreshOptionProperties();
        RefreshStudentWhy();
        GenerateSecret();
    }

    private async Task RequestResetAppDataAsync()
    {
        if (ResetAppDataRequested is { } requested)
        {
            await requested().ConfigureAwait(true);
        }
    }

    private void SavePreferences()
    {
        _preferencesService.SaveOptions(CreateOptions(), _passwordLength, _pinLength, _wordCount);
    }

    private void SaveAppearance()
    {
        _preferencesService.SaveAppearance(Theme, ClearClipboardAfterCopy, AutoLockVault, _language);
    }

    private void SaveTray()
    {
        _preferencesService.SaveTray(StayInTray, GlobalHotkeys);
    }

    private static bool SetField<T>(ref T field, T value)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        return true;
    }

    private bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (!SetField(ref field, value))
        {
            return false;
        }

        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
