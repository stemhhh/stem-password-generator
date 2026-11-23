using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using Microsoft.UI.Xaml.Media.Imaging;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Windows.Security.Credentials.UI;
using Windows.Storage.Streams;

namespace StemPasswordGenerator.ViewModels;

public sealed class VaultViewModel : INotifyPropertyChanged
{
    private readonly VaultStore _store;
    private readonly ClipboardService _clipboard;
    private readonly OccupantCatalogStore _occupants = new();
    private readonly UserPreferencesService _preferences = new();
    private readonly VaultStore _decoyStore = new();
    private readonly SecretGenerator _secretGenerator = new();
    private readonly RelayCommand _saveItemCommand;
    private readonly RelayCommand _deleteItemCommand;
    private readonly RelayCommand _copyUsernameCommand;
    private readonly RelayCommand _copyPasswordCommand;

    private string _pendingBrowserContainer = string.Empty;
    private bool _needsSetup = true;
    private bool _isLocked = true;
    private bool _isBusy;
    private bool _changingMaster;
    private bool _isPasswordVisible;
    private bool _helloAvailable;
    private string _statusMessage = string.Empty;
    private string? _statusKey;
    private object[] _statusArgs = [];
    private bool _writingStatus;
    private DateTimeOffset? _humanSkipLast;
    private string _searchQuery = string.Empty;
    private string _masterPassword = string.Empty;
    private string _confirmPassword = string.Empty;
    private VaultListItem? _selected;
    private Guid _editingId = Guid.Empty;
    private int _editKindIndex;
    private string _editTitle = string.Empty;
    private string _editUrl = string.Empty;
    private string _editBrowserContainer = string.Empty;
    private string _editUsername = string.Empty;
    private string _editPassword = string.Empty;
    private string _editNotes = string.Empty;
    private string _editTotpSecret = string.Empty;
    private string _totpCode = string.Empty;
    private int _totpSecondsLeft;
    private string _editAliasEmail = string.Empty;
    private string _editMailbox = string.Empty;
    private string _editCardholder = string.Empty;
    private string _editCardNumber = string.Empty;
    private string _editCardExpiry = string.Empty;
    private string _editCardCvv = string.Empty;
    private string _editFullName = string.Empty;
    private string _editPhone = string.Empty;
    private string _editAddress = string.Empty;
    private string _primaryEmail = string.Empty;
    private string _aliasDomain = string.Empty;
    private string _mailboxesText = string.Empty;
    private string _newPersonName = string.Empty;
    private string _newMailboxLabel = "Personal";
    private string _newMailboxEmail = string.Empty;
    private VaultOccupant? _selectedOccupant;
    private MailboxProfile? _selectedMailboxProfile;
    private bool _loadingOccupants;
    private bool _loadingMailboxes;
    private PendingLogin? _pendingLogin;
    private readonly List<PendingSeal> _pendingSeals = [];
    private int _failedUnlocks;
    private int _humanFailures;
    private bool _isPendingHuman;
    private bool _factoryResetPending;
    private bool _wipingAppData;
    private bool _useMasterKeyboard;
    private readonly MasterKeyboardController _masterKeyboard = new();
    private bool _recoveryPrompted;
    private HumanPresenceChallenge? _human;
    private string _humanDisplay = string.Empty;
    private Func<Task>? _afterHuman;
    private DateTimeOffset _nextUnlockAllowed = DateTimeOffset.MinValue;
    private CancellationTokenSource? _hidePasswordCancellation;
    private CancellationTokenSource? _totpCancellation;
    private CancellationTokenSource? _totpDebounceCancellation;
    private CancellationTokenSource? _searchDebounceCancellation;
    private CancellationTokenSource? _wifiQrDebounceCancellation;
    private ObservableCollection<VaultListItem> _visibleItems = [];
    private ObservableCollection<HealthFinding> _healthFindings = [];
    private int _healthGeneration;
    private string _homeFolderName = string.Empty;
    private bool _isDecoySession;
    private bool _isEditingDecoy;
    private bool _decoyExists;
    private int _editWifiSecurityIndex;
    private BitmapImage? _wifiQrImage;
    private int _wifiQrGeneration;
    private UsbDriveInfo? _selectedUsbDrive;
    private string _usbVolumeLabel = "STEMKEY";
    private int _usbFileSystemIndex;
    private int _usbClusterIndex;
    private bool _usbQuickFormat = true;
    private bool _usbFormatFirst = true;
    private bool _usbUnlockAvailable;
            private bool _recoveryConfigured;
    private bool _isMediaSection;
    private bool _isAuditSection;
    private string _mediaGalleryCategory = MediaCategory.Photo;
    private string _mediaSortKey = MediaGalleryRules.SortDateNew;
    private bool _rebuildingMediaSort;
    private MediaGalleryRow? _selectedMedia;
    private int _mediaThumbGeneration;
    private readonly Dictionary<Guid, BitmapImage> _mediaThumbs = [];
    private const long MaximumGalleryPreviewBytes = 8L * 1024 * 1024;
    private string _unlockMethod = AuditMethod.Master;
    private AuditRow? _selectedAudit;
    private FolderFilterChoice? _selectedAuditFilter;
    private bool _rebuildingAuditFilters;
    private string _editFolder = string.Empty;
    private FolderFilterChoice? _selectedFolderFilter;
    private bool _rebuildingFolders;
    private IReadOnlyList<DateTimeOffset> _remoteSamples = [];
    private bool _clockConfirmed;
    private string _editMediaTitle = string.Empty;
    private string _mediaOriginalName = string.Empty;
    private string _mediaSizeLabel = string.Empty;
    private string _mediaTypeLabel = string.Empty;
    private BitmapImage? _mediaPreview;
    private const long MaximumInMemoryPreviewBytes = 20L * 1024 * 1024;

    public VaultViewModel(VaultStore store, ClipboardService clipboard)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _clipboard = clipboard ?? throw new ArgumentNullException(nameof(clipboard));
        _humanSkipLast = HumanPresenceSkipFile.Read();

        CreateVaultCommand = new RelayCommand(async () => await CreateVaultAsync(), () => !IsBusy);
        UnlockCommand = new RelayCommand(async () => await UnlockAsync(), () => !IsBusy);
        SubmitHumanDigitCommand = new RelayCommand<string>(digit => SubmitHumanDigit(digit));
        CancelHumanVerificationCommand = new RelayCommand(CancelHumanVerification, () => IsPendingHumanVerification);
        PressMasterKeyCommand = new RelayCommand<string>(PressMasterKey);
        MasterBackspaceCommand = new RelayCommand(MasterBackspace);
        UnlockWithHelloCommand = new RelayCommand(async () => await UnlockWithHelloAsync(), () => !IsBusy && HelloAvailable);
        LockCommand = new RelayCommand(() => Lock(), () => IsUnlocked);
        NewLoginCommand = new RelayCommand(() => { ShowItemsWorkspace(); NewItem(VaultItemKind.Login); }, () => IsUnlocked);
        NewAliasCommand = new RelayCommand(() => { ShowItemsWorkspace(); NewItem(VaultItemKind.Alias); }, () => IsUnlocked);
        NewCardCommand = new RelayCommand(() => { ShowItemsWorkspace(); NewItem(VaultItemKind.Card); }, () => IsUnlocked);
        NewNoteCommand = new RelayCommand(() => { ShowItemsWorkspace(); NewItem(VaultItemKind.Note); }, () => IsUnlocked);
        NewRecoveryCommand = new RelayCommand(() => { ShowItemsWorkspace(); NewItem(VaultItemKind.Recovery); }, () => IsUnlocked);
        NewWifiCommand = new RelayCommand(() => { ShowItemsWorkspace(); NewItem(VaultItemKind.Wifi); }, () => IsUnlocked);
        NewSecretCommand = new RelayCommand(() => { ShowItemsWorkspace(); NewItem(VaultItemKind.Secret); }, () => IsUnlocked);
        ShowLoginsCommand = new RelayCommand(ShowItemsWorkspace, () => IsUnlocked);
        ShowMediaCommand = new RelayCommand(() => OpenMediaGallery(MediaCategory.Photo), () => IsUnlocked);
        AddMediaPhotoCommand = new RelayCommand(async () => await AddMediaAsync(MediaCategory.Photo), () => IsUnlocked);
        AddMediaVideoCommand = new RelayCommand(async () => await AddMediaAsync(MediaCategory.Video), () => IsUnlocked);
        AddMediaAudioCommand = new RelayCommand(async () => await AddMediaAsync(MediaCategory.Audio), () => IsUnlocked);
        AddMediaFileCommand = new RelayCommand(async () => await AddMediaAsync(MediaCategory.File), () => IsUnlocked);
        AddCurrentMediaCommand = new RelayCommand(async () => await AddMediaAsync(MediaGalleryCategory), () => IsUnlocked);
        ExportMediaCommand = new RelayCommand(async () => await ExportMediaAsync(), () => IsUnlocked && IsMediaSection && _editingId != Guid.Empty);
        SaveMediaCommand = new RelayCommand(async () => await SaveMediaTitleAsync(), () => IsUnlocked && IsMediaSection && _editingId != Guid.Empty);
        _saveItemCommand = new RelayCommand(async () => await SaveItemAsync(), CanSaveItem);
        _deleteItemCommand = new RelayCommand(async () => await DeleteItemAsync(), () => IsUnlocked && _editingId != Guid.Empty);
        _copyUsernameCommand = new RelayCommand(() => Copy(_editUsername), () => !string.IsNullOrEmpty(_editUsername));
        _copyPasswordCommand = new RelayCommand(() => Copy(_editPassword), () => !string.IsNullOrEmpty(_editPassword));
        SaveItemCommand = _saveItemCommand;
        DeleteItemCommand = _deleteItemCommand;
        CopyUsernameCommand = _copyUsernameCommand;
        CopyPasswordCommand = _copyPasswordCommand;
        CopyRecoveryCodesCommand = new RelayCommand(() => Copy(EditNotes), () => !string.IsNullOrWhiteSpace(EditNotes));
        TogglePasswordVisibilityCommand = new RelayCommand(() => IsPasswordVisible = !IsPasswordVisible);
        CopyTotpCommand = new RelayCommand(() => Copy(TotpCode), () => !string.IsNullOrEmpty(TotpCode));
        CopyAliasCommand = new RelayCommand(() => Copy(EditAliasEmail), () => !string.IsNullOrEmpty(EditAliasEmail));
        GenerateTotpCommand = new RelayCommand(GenerateTotp, () => IsUnlocked);
        GenerateAliasCommand = new RelayCommand(GenerateAlias, () => IsUnlocked);
        SaveSettingsCommand = new RelayCommand(async () => await SaveSettingsAsync(), () => IsUnlocked);
        EnableHelloCommand = new RelayCommand(async () => await EnableHelloAsync(), () => IsUnlocked && !IsDecoySession);
        ShareItemCommand = new RelayCommand(async () => await ShareCurrentAsync(), () => IsUnlocked && _editingId != Guid.Empty);
        ShareVaultCommand = new RelayCommand(async () => await ShareVaultAsync(), () => IsUnlocked);
        ImportShareCommand = new RelayCommand(async () => await ImportShareAsync(), () => IsUnlocked);
        ImportCsvCommand = new RelayCommand(async () => await ImportCsvAsync(), CanImportCsv);
        ExportCsvCommand = new RelayCommand(async () => await ExportCsvAsync(), CanExportCsv);
        ExportPortableCommand = new RelayCommand(async () => await ExportPortableAsync(), CanExportPortable);
        OpenPortableCommand = new RelayCommand(async () => await OpenPortableAsync(), CanOpenPortable);
        EmergencyKitCommand = new RelayCommand(async () => await ExportEmergencyAsync(), () => IsUnlocked);
        CreateShamirCommand = new RelayCommand(async () => await CreateShamirCardsAsync(), CanCreateShamir);
        RecoverShamirCommand = new RelayCommand(async () => await RecoverShamirAsync(), CanRecoverShamir);
        ForgotMasterCommand = new RelayCommand(async () => await ForgotMasterAsync(), CanForgotMaster);
        ChangeMasterCommand = new RelayCommand(async () => await ChangeMasterAsync(required: false), CanChangeMaster);
        SetupRecoveryCommand = new RelayCommand(async () => await SetupRecoveryAsync(), CanSetupRecovery);
        RefreshUsbDrivesCommand = new RelayCommand(RefreshUsbDrives, () => !IsBusy);
        PrepareUsbKeyCommand = new RelayCommand(async () => await PrepareUsbKeyAsync(), CanPrepareUsbKey);
        RestoreUsbStorageCommand = new RelayCommand(async () => await RestoreUsbStorageAsync(), CanRestoreUsbStorage);
        RemoveUsbUnlockCommand = new RelayCommand(async () => await RemoveUsbUnlockAsync(), CanRemoveUsbUnlock);
        UnlockWithUsbCommand = new RelayCommand(async () => await UnlockWithUsbAsync(), CanUnlockWithUsb);
        AddAttachmentCommand = new RelayCommand(async () => await AddAttachmentAsync(), () => IsUnlocked);
        AutofillCommand = new RelayCommand(() => AutofillRequested?.Invoke(), () => IsUnlocked);
        ComposeAliasCommand = new RelayCommand(ComposeAlias, () => !string.IsNullOrEmpty(EditAliasEmail));
        AddPersonCommand = new RelayCommand(async () => await AddPersonAsync(), CanAddPerson);
        SwitchPersonCommand = new RelayCommand(async () => await SwitchSelectedPersonAsync(null), () => SelectedOccupant is not null);
        AddMailboxCommand = new RelayCommand(async () => await AddMailboxAsync(), CanAddMailbox);
        RemoveMailboxCommand = new RelayCommand(async () => await RemoveSelectedMailboxAsync(), () => IsUnlocked && SelectedMailboxProfile is not null);
        MakeDefaultMailboxCommand = new RelayCommand(async () => await MakeDefaultMailboxAsync(), () => IsUnlocked && SelectedMailboxProfile is not null);
        RemovePersonCommand = new RelayCommand(async () => await RemoveCurrentPersonAsync(), () => IsUnlocked && !IsDecoySession);
        PanicLockCommand = new RelayCommand(() => _ = PanicLockAsync(), () => !IsBusy);
        ResetAppDataCommand = new RelayCommand(async () => await ResetAppDataAsync(), () => !IsBusy);
        CreateDecoyCommand = new RelayCommand(async () => await CreateOrReplaceDecoyAsync(), CanCreateDecoy);
        EditDecoyCommand = new RelayCommand(async () => await EditDecoyAsync(), CanEditDecoy);
        RemoveDecoyCommand = new RelayCommand(async () => await RemoveDecoyAsync(), CanRemoveDecoy);
        DoneEditingDecoyCommand = new RelayCommand(() => Lock(), () => IsEditingDecoy);
        UiStrings.LanguageChanged += OnUiLanguageChanged;
        RebuildMediaSortChoices();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public Func<Task<(string Name, byte[] Data)?>>? PickFileRequested { get; set; }

    public Func<string, Task<(string Name, Stream Stream, long Length)?>>? PickMediaRequested { get; set; }

    public Func<string, Func<Stream, Task>, Task<bool>>? SaveMediaRequested { get; set; }

    public Func<string, byte[], Task>? SaveFileRequested { get; set; }

    public Action? AutofillRequested { get; set; }

    public Action<string>? ComposeRequested { get; set; }

    public Func<string, Task<string?>>? AskSharePasswordAsync { get; set; }

    public Func<string, string, string, Task<string?>>? AskLabeledPasswordAsync { get; set; }

    public Func<IReadOnlyList<ShamirCard>, Task<bool>>? SaveShamirCardsAsync { get; set; }

    public Func<Task<IReadOnlyList<string>?>>? PickTextFilesAsync { get; set; }

    public Func<RecoveryMaterials, Task<bool>>? ShowRecoveryKitAsync { get; set; }

    public Func<Task<string?>>? AskRecoverySecretAsync { get; set; }

    public Func<Task<(string Password, string Confirm)?>>? AskNewMasterAsync { get; set; }

    public ObservableCollection<VaultListItem> VisibleItems
    {
        get => _visibleItems;
        private set => SetProperty(ref _visibleItems, value);
    }

    public ObservableCollection<HealthFinding> HealthFindings
    {
        get => _healthFindings;
        private set => SetProperty(ref _healthFindings, value);
    }

    public ObservableCollection<string> AttachmentNames { get; } = [];

    public ObservableCollection<PasswordHistoryRow> PasswordHistory { get; } = [];

    public bool HasPasswordHistory => PasswordHistory.Count > 0;

    public RelayCommand CreateVaultCommand { get; }
    public RelayCommand UnlockCommand { get; }
    public RelayCommand<string> SubmitHumanDigitCommand { get; }
    public RelayCommand CancelHumanVerificationCommand { get; }
    public RelayCommand<string> PressMasterKeyCommand { get; }
    public RelayCommand MasterBackspaceCommand { get; }
    public RelayCommand UnlockWithHelloCommand { get; }
    public RelayCommand LockCommand { get; }
    public RelayCommand NewLoginCommand { get; }
    public RelayCommand NewAliasCommand { get; }
    public RelayCommand NewCardCommand { get; }
    public RelayCommand NewNoteCommand { get; }
    public RelayCommand NewRecoveryCommand { get; }
    public RelayCommand NewWifiCommand { get; }
    public RelayCommand NewSecretCommand { get; }
    public RelayCommand ShowLoginsCommand { get; }
    public RelayCommand ShowMediaCommand { get; }
    public RelayCommand AddMediaPhotoCommand { get; }
    public RelayCommand AddMediaVideoCommand { get; }
    public RelayCommand AddMediaAudioCommand { get; }
    public RelayCommand AddMediaFileCommand { get; }
    public RelayCommand AddCurrentMediaCommand { get; }
    public RelayCommand ExportMediaCommand { get; }
    public RelayCommand SaveMediaCommand { get; }
    public RelayCommand SaveItemCommand { get; }
    public RelayCommand DeleteItemCommand { get; }
    public RelayCommand CopyUsernameCommand { get; }
    public RelayCommand CopyPasswordCommand { get; }
    public RelayCommand CopyRecoveryCodesCommand { get; }
    public RelayCommand TogglePasswordVisibilityCommand { get; }
    public RelayCommand CopyTotpCommand { get; }
    public RelayCommand CopyAliasCommand { get; }
    public RelayCommand GenerateTotpCommand { get; }
    public RelayCommand GenerateAliasCommand { get; }
    public RelayCommand SaveSettingsCommand { get; }
    public RelayCommand EnableHelloCommand { get; }
    public RelayCommand ShareItemCommand { get; }
    public RelayCommand ShareVaultCommand { get; }
    public RelayCommand ImportShareCommand { get; }
    public RelayCommand ImportCsvCommand { get; }
    public RelayCommand ExportCsvCommand { get; }
    public RelayCommand ExportPortableCommand { get; }
    public RelayCommand OpenPortableCommand { get; }
    public RelayCommand EmergencyKitCommand { get; }
    public RelayCommand CreateShamirCommand { get; }
    public RelayCommand RecoverShamirCommand { get; }

    public RelayCommand ForgotMasterCommand { get; }

    public RelayCommand ChangeMasterCommand { get; }

    public RelayCommand SetupRecoveryCommand { get; }
    public RelayCommand RefreshUsbDrivesCommand { get; }
    public RelayCommand PrepareUsbKeyCommand { get; }
    public RelayCommand RestoreUsbStorageCommand { get; }
    public RelayCommand RemoveUsbUnlockCommand { get; }
    public RelayCommand UnlockWithUsbCommand { get; }
    public RelayCommand AddAttachmentCommand { get; }
    public RelayCommand AutofillCommand { get; }
    public RelayCommand ComposeAliasCommand { get; }
    public RelayCommand AddPersonCommand { get; }
    public RelayCommand SwitchPersonCommand { get; }
    public RelayCommand AddMailboxCommand { get; }
    public RelayCommand RemoveMailboxCommand { get; }
    public RelayCommand MakeDefaultMailboxCommand { get; }
    public RelayCommand RemovePersonCommand { get; }
    public RelayCommand PanicLockCommand { get; }
    public RelayCommand ResetAppDataCommand { get; }
    public RelayCommand CreateDecoyCommand { get; }
    public RelayCommand EditDecoyCommand { get; }
    public RelayCommand RemoveDecoyCommand { get; }
    public RelayCommand DoneEditingDecoyCommand { get; }

    public Action? PanicCompleted { get; set; }

    public Action? VaultPageRequested { get; set; }

    public Action? FactoryResetCompleted { get; set; }

    public Func<string, string, string?, Task<bool>>? ConfirmAsync { get; set; }

    public ObservableCollection<VaultOccupant> Occupants { get; } = [];

    public ObservableCollection<MailboxProfile> MailboxProfiles { get; } = [];

    public bool NeedsSetup
    {
        get => _needsSetup;
        private set
        {
            if (SetProperty(ref _needsSetup, value))
            {
                OnPropertyChanged(nameof(IsUnlocked));
                OnPropertyChanged(nameof(ShowSetup));
                OnPropertyChanged(nameof(ShowUnlock));
                OnPropertyChanged(nameof(ShowHumanVerification));
                OnPropertyChanged(nameof(ShowWorkspace));
                RecoverShamirCommand.NotifyCanExecuteChanged();
                ForgotMasterCommand.NotifyCanExecuteChanged();
                ChangeMasterCommand.NotifyCanExecuteChanged();
                OpenPortableCommand.NotifyCanExecuteChanged();
                NotifyUsbCommands();
            }
        }
    }

    public bool IsLocked
    {
        get => _isLocked;
        private set
        {
            if (SetProperty(ref _isLocked, value))
            {
                OnPropertyChanged(nameof(IsUnlocked));
                OnPropertyChanged(nameof(ShowSetup));
                OnPropertyChanged(nameof(ShowUnlock));
                OnPropertyChanged(nameof(ShowHumanVerification));
                OnPropertyChanged(nameof(ShowWorkspace));
                LockCommand.NotifyCanExecuteChanged();
                RecoverShamirCommand.NotifyCanExecuteChanged();
                ForgotMasterCommand.NotifyCanExecuteChanged();
                ChangeMasterCommand.NotifyCanExecuteChanged();
                SetupRecoveryCommand.NotifyCanExecuteChanged();
                NotifyUsbCommands();
                NewLoginCommand.NotifyCanExecuteChanged();
                NewAliasCommand.NotifyCanExecuteChanged();
                NewCardCommand.NotifyCanExecuteChanged();
                NewNoteCommand.NotifyCanExecuteChanged();
                NewRecoveryCommand.NotifyCanExecuteChanged();
                NewWifiCommand.NotifyCanExecuteChanged();
                NewSecretCommand.NotifyCanExecuteChanged();
                NotifyMediaCommands();
                NotifyEditorCommands();
                NotifyPersonCommands();
            }
        }
    }

    public bool IsUnlocked => _store.IsUnlocked && !NeedsSetup && !IsLocked && !_factoryResetPending;

    public bool IsPendingHumanVerification =>
        _isPendingHuman && (_store.IsPendingHumanVerification || _factoryResetPending);

    public bool ShowSetup => NeedsSetup;

    public bool ShowUnlock => !NeedsSetup && IsLocked && !IsPendingHumanVerification && !_factoryResetPending;

    public bool ShowHumanVerification => _isPendingHuman && (_store.IsPendingHumanVerification || _factoryResetPending);

    public bool ShowWorkspace => IsUnlocked;

    public string HumanVerificationHeading =>
        UiStrings.Get(_factoryResetPending ? "ResetAppHumanTitle" : "HumanVerificationTitle");

    public string HumanVerificationDetail =>
        UiStrings.Get(_factoryResetPending ? "ResetAppHumanBody" : "HumanVerificationBody");

    public string HumanChallengeText => _humanDisplay;

    public ObservableCollection<string> HumanKeypad { get; } = [];

    public IReadOnlyList<MasterKeyboardRow> MasterKeyboardRows => _masterKeyboard.Rows;

    public int MasterKeyboardRevision { get; private set; }

    public bool UseMasterKeyboard
    {
        get => _useMasterKeyboard;
        set
        {
            if (SetProperty(ref _useMasterKeyboard, value) && value)
            {
                _masterKeyboard.Reset();
                NotifyMasterKeyboard();
            }
        }
    }

    public bool IsMediaSection
    {
        get => _isMediaSection;
        set
        {
            if (value && _isAuditSection)
            {
                _isAuditSection = false;
                OnPropertyChanged(nameof(IsAuditSection));
            }

            if (SetProperty(ref _isMediaSection, value))
            {
                NotifyWorkspace();
                ClearMediaPreview();
                _editingId = Guid.Empty;
                _selected = null;
                OnPropertyChanged(nameof(SelectedItem));
                ResetFolderFilter();
                RefreshVisibleItems();
                NotifyMediaCommands();
                NotifyEditorCommands();
                if (IsMediaSection)
                {
                    if (VisibleItems.Count > 0)
                    {
                        SelectedItem = VisibleItems[0];
                    }
                    else
                    {
                        SetStatus("MediaEmpty");
                    }
                }
                else if (!IsAuditSection && VisibleItems.Count > 0)
                {
                    SelectedItem = VisibleItems[0];
                }
            }
        }
    }

    public bool IsAuditSection
    {
        get => _isAuditSection;
        set
        {
            if (value && _isMediaSection)
            {
                _isMediaSection = false;
                OnPropertyChanged(nameof(IsMediaSection));
                ClearMediaPreview();
            }

            if (SetProperty(ref _isAuditSection, value))
            {
                NotifyWorkspace();
                if (value)
                {
                    RebuildAuditFilters();
                    RefreshAudit();
                }
            }
        }
    }

    public bool ShowLoginSection => !IsMediaSection && !IsAuditSection;

    public bool ShowMediaEditor => IsMediaSection && !IsAuditSection;

    public bool ShowMediaPhotoGallery => ShowMediaEditor && MediaGalleryCategory == MediaCategory.Photo;

    public bool ShowMediaVideoGallery => ShowMediaEditor && MediaGalleryCategory == MediaCategory.Video;

    public bool ShowMediaAudioGallery => ShowMediaEditor && MediaGalleryCategory == MediaCategory.Audio;

    public bool ShowMediaFileExplorer => ShowMediaEditor && MediaGalleryCategory == MediaCategory.File;

    public bool ShowMediaCardGallery => ShowMediaVideoGallery || ShowMediaAudioGallery;

    public string MediaGalleryCategory
    {
        get => _mediaGalleryCategory;
        private set
        {
            if (!MediaGalleryRules.IsCategory(value))
            {
                value = MediaCategory.Photo;
            }

            if (SetProperty(ref _mediaGalleryCategory, value))
            {
                NotifyWorkspace();
            }
        }
    }

    public void OpenMediaGallery(string category)
    {
        MediaGalleryCategory = category;
        IsAuditSection = false;
        if (!IsMediaSection)
        {
            IsMediaSection = true;
            return;
        }

        NotifyWorkspace();
        RefreshVisibleItems();
    }

    public bool ShowAuditSection => IsAuditSection;

    public bool ShowFolderFilter => !IsAuditSection;

    public string VaultWorkspaceTitle => IsAuditSection
        ? UiStrings.Get("VaultSectionActivity")
        : IsMediaSection
            ? MediaGalleryTitle
            : UiStrings.Get("VaultSectionItems");

    public string MediaGalleryTitle => MediaGalleryCategory switch
    {
        MediaCategory.Video => UiStrings.Get("MediaGalleryVideos"),
        MediaCategory.Audio => UiStrings.Get("MediaGalleryAudio"),
        MediaCategory.File => UiStrings.Get("MediaGalleryFiles"),
        _ => UiStrings.Get("MediaGalleryPhotos")
    };

    public string FolderFilterHeader => IsMediaSection
        ? UiStrings.Get("MediaTagFilter")
        : UiStrings.Get("FolderFilter");

    public string MediaAddCurrentLabel => MediaGalleryCategory switch
    {
        MediaCategory.Video => UiStrings.Get("MediaAddVideo"),
        MediaCategory.Audio => UiStrings.Get("MediaAddAudio"),
        MediaCategory.File => UiStrings.Get("MediaAddFile"),
        _ => UiStrings.Get("MediaAddPhoto")
    };

    public ObservableCollection<MediaGalleryRow> VisibleMedia { get; } = [];

    public ObservableCollection<FolderFilterChoice> MediaSortChoices { get; } = [];

    public FolderFilterChoice? SelectedMediaSort
    {
        get => MediaSortChoices.FirstOrDefault(choice => choice.Key == _mediaSortKey) ?? MediaSortChoices.FirstOrDefault();
        set
        {
            if (_rebuildingMediaSort)
            {
                return;
            }

            var key = value?.Key ?? MediaGalleryRules.SortDateNew;
            if (_mediaSortKey == key)
            {
                return;
            }

            _mediaSortKey = key;
            OnPropertyChanged();
            if (IsMediaSection)
            {
                RefreshVisibleItems();
            }
        }
    }

    public MediaGalleryRow? SelectedMedia
    {
        get => _selectedMedia;
        set
        {
            if (SetProperty(ref _selectedMedia, value) && value is not null && IsMediaSection)
            {
                var match = VisibleItems.FirstOrDefault(item => item.Id == value.Id);
                if (!ReferenceEquals(SelectedItem, match))
                {
                    SelectedItem = match;
                }
            }
        }
    }

    public ObservableCollection<FolderFilterChoice> FolderFilters { get; } = [];

    public ObservableCollection<FolderFilterChoice> AuditFilters { get; } = [];

    public ObservableCollection<AuditRow> VisibleAudit { get; } = [];

    public ObservableCollection<string> FolderSuggestions { get; } = [];

    public FolderFilterChoice? SelectedFolderFilter
    {
        get => _selectedFolderFilter;
        set
        {
            if (_rebuildingFolders)
            {
                _selectedFolderFilter = value;
                OnPropertyChanged();
                return;
            }

            if (SetProperty(ref _selectedFolderFilter, value))
            {
                RefreshVisibleItems();
            }
        }
    }

    public FolderFilterChoice? SelectedAuditFilter
    {
        get => _selectedAuditFilter;
        set
        {
            if (_rebuildingAuditFilters)
            {
                _selectedAuditFilter = value;
                OnPropertyChanged();
                return;
            }

            if (SetProperty(ref _selectedAuditFilter, value))
            {
                RefreshAudit();
            }
        }
    }

    public AuditRow? SelectedAudit
    {
        get => _selectedAudit;
        set
        {
            if (SetProperty(ref _selectedAudit, value))
            {
                OnPropertyChanged(nameof(HasSelectedAudit));
            }
        }
    }

    public bool HasSelectedAudit => SelectedAudit is not null;

    public string EditFolder
    {
        get => _editFolder;
        set => SetProperty(ref _editFolder, value);
    }

    public string EditMediaTitle
    {
        get => _editMediaTitle;
        set => SetProperty(ref _editMediaTitle, value);
    }

    public string MediaOriginalName
    {
        get => _mediaOriginalName;
        private set => SetProperty(ref _mediaOriginalName, value);
    }

    public string MediaSizeLabel
    {
        get => _mediaSizeLabel;
        private set => SetProperty(ref _mediaSizeLabel, value);
    }

    public string MediaTypeLabel
    {
        get => _mediaTypeLabel;
        private set => SetProperty(ref _mediaTypeLabel, value);
    }

    public BitmapImage? MediaPreview
    {
        get => _mediaPreview;
        private set
        {
            if (SetProperty(ref _mediaPreview, value))
            {
                OnPropertyChanged(nameof(HasMediaPreview));
            }
        }
    }

    public bool HasMediaPreview => MediaPreview is not null;

    public bool HelloAvailable
    {
        get => _helloAvailable;
        private set
        {
            if (SetProperty(ref _helloAvailable, value))
            {
                UnlockWithHelloCommand.NotifyCanExecuteChanged();
                ForgotMasterCommand.NotifyCanExecuteChanged();
                ChangeMasterCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public bool UsbUnlockAvailable
    {
        get => _usbUnlockAvailable;
        private set
        {
            if (SetProperty(ref _usbUnlockAvailable, value))
            {
                OnPropertyChanged(nameof(UsbHint));
                NotifyUsbCommands();
            }
        }
    }

    public bool RecoveryConfigured
    {
        get => _recoveryConfigured;
        private set
        {
            if (SetProperty(ref _recoveryConfigured, value))
            {
                OnPropertyChanged(nameof(RecoveryStatus));
                ForgotMasterCommand.NotifyCanExecuteChanged();
                ChangeMasterCommand.NotifyCanExecuteChanged();
                SetupRecoveryCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public string RecoveryStatus => RecoveryConfigured
        ? UiStrings.Get("RecoveryStatusOn")
        : UiStrings.Get("RecoveryStatusOff");

    public ObservableCollection<UsbDriveInfo> UsbDrives { get; } = [];

    public UsbDriveInfo? SelectedUsbDrive
    {
        get => _selectedUsbDrive;
        set
        {
            if (SetProperty(ref _selectedUsbDrive, value))
            {
                NotifyUsbCommands();
                if (value is not null && string.IsNullOrWhiteSpace(UsbVolumeLabel))
                {
                    UsbVolumeLabel = string.IsNullOrWhiteSpace(value.Label) ? "STEMKEY" : value.Label;
                }
            }
        }
    }

    public string UsbVolumeLabel
    {
        get => _usbVolumeLabel;
        set => SetProperty(ref _usbVolumeLabel, value ?? string.Empty);
    }

    public int UsbFileSystemIndex
    {
        get => _usbFileSystemIndex;
        set => SetProperty(ref _usbFileSystemIndex, Math.Clamp(value, 0, UsbDriveRules.FileSystems.Length - 1));
    }

    public int UsbClusterIndex
    {
        get => _usbClusterIndex;
        set => SetProperty(ref _usbClusterIndex, Math.Clamp(value, 0, UsbDriveRules.ClusterBytes.Length - 1));
    }

    public bool UsbQuickFormat
    {
        get => _usbQuickFormat;
        set => SetProperty(ref _usbQuickFormat, value);
    }

    public bool UsbFormatFirst
    {
        get => _usbFormatFirst;
        set => SetProperty(ref _usbFormatFirst, value);
    }

    public string UsbHint => UsbUnlockAvailable ? UiStrings.Get("UsbKeyRegistered") : UiStrings.Get("UsbKeyNotRegistered");

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetProperty(ref _isBusy, value))
            {
                CreateVaultCommand.NotifyCanExecuteChanged();
                UnlockCommand.NotifyCanExecuteChanged();
                UnlockWithHelloCommand.NotifyCanExecuteChanged();
                AddPersonCommand.NotifyCanExecuteChanged();
                CreateShamirCommand.NotifyCanExecuteChanged();
                RecoverShamirCommand.NotifyCanExecuteChanged();
                ForgotMasterCommand.NotifyCanExecuteChanged();
                ChangeMasterCommand.NotifyCanExecuteChanged();
                SetupRecoveryCommand.NotifyCanExecuteChanged();
                NotifyUsbCommands();
                NotifyPanicCommands();
                OpenPortableCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public bool IsPasswordVisible
    {
        get => _isPasswordVisible;
        set
        {
            if (SetProperty(ref _isPasswordVisible, value))
            {
                OnPropertyChanged(nameof(PasswordRevealLabel));
                if (value)
                {
                    SchedulePasswordHide();
                }
            }
        }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set
        {
            if (SetProperty(ref _statusMessage, value) && !_writingStatus)
            {
                _statusKey = null;
                _statusArgs = [];
            }
        }
    }

    public void SetStatus(string key, params object[] args)
    {
        _statusKey = key;
        _statusArgs = args;
        _writingStatus = true;
        try
        {
            StatusMessage = args.Length == 0 ? UiStrings.Get(key) : UiStrings.Format(key, args);
        }
        finally
        {
            _writingStatus = false;
        }
    }

    public void ClearStatus()
    {
        _statusKey = null;
        _statusArgs = [];
        _writingStatus = true;
        try
        {
            StatusMessage = string.Empty;
        }
        finally
        {
            _writingStatus = false;
        }
    }

    private void SetStatusRaw(string message)
    {
        _statusKey = null;
        _statusArgs = [];
        _writingStatus = true;
        try
        {
            StatusMessage = message;
        }
        finally
        {
            _writingStatus = false;
        }
    }

    private static bool IsPlaceholderPersonName(string name) =>
        name.Equals("My vault", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Mi bóveda", StringComparison.OrdinalIgnoreCase);

    private void ApplyDefaultPersonName()
    {
        if (string.IsNullOrWhiteSpace(NewPersonName) || IsPlaceholderPersonName(NewPersonName))
        {
            NewPersonName = UiStrings.Get("MyVault");
        }
    }

    public string SearchQuery
    {
        get => _searchQuery;
        set
        {
            if (SetProperty(ref _searchQuery, value))
            {
                DebounceSearch();
            }
        }
    }

    public string MasterPassword { get => _masterPassword; set => SetProperty(ref _masterPassword, value); }

    public string ConfirmPassword { get => _confirmPassword; set => SetProperty(ref _confirmPassword, value); }

    public VaultListItem? SelectedItem
    {
        get => _selected;
        set
        {
            if (SetProperty(ref _selected, value) && value is not null)
            {
                if (IsMediaSection)
                {
                    var media = _store.FindMedia(value.Id);
                    if (media is not null)
                    {
                        _ = LoadMediaEditorAsync(media);
                    }

                    var row = VisibleMedia.FirstOrDefault(item => item.Id == value.Id);
                    if (!ReferenceEquals(_selectedMedia, row))
                    {
                        _selectedMedia = row;
                        OnPropertyChanged(nameof(SelectedMedia));
                    }
                }
                else
                {
                    var item = _store.Find(value.Id);
                    if (item is not null)
                    {
                        LoadEditor(item);
                    }
                }
            }
        }
    }

    public int EditKindIndex
    {
        get => _editKindIndex;
        set
        {
            if (SetProperty(ref _editKindIndex, value))
            {
                OnPropertyChanged(nameof(ShowLoginFields));
                OnPropertyChanged(nameof(ShowAliasFields));
                OnPropertyChanged(nameof(ShowMailboxPicker));
                OnPropertyChanged(nameof(ShowCardFields));
                OnPropertyChanged(nameof(ShowNoteFields));
                OnPropertyChanged(nameof(ShowIdentityFields));
                OnPropertyChanged(nameof(ShowRecoveryFields));
                OnPropertyChanged(nameof(ShowWifiFields));
                OnPropertyChanged(nameof(ShowSecretFields));
                OnPropertyChanged(nameof(ShowPasswordField));
                OnPropertyChanged(nameof(ShowPasswordHistory));
                OnPropertyChanged(nameof(NameHeader));
                OnPropertyChanged(nameof(NamePlaceholderText));
                OnPropertyChanged(nameof(PasswordFieldHeader));
                OnPropertyChanged(nameof(NotesHeader));
                OnPropertyChanged(nameof(EditorIdenticonSeed));
                NotifyEditorCommands();
                DebounceWifiQr();
            }
        }
    }

    public bool ShowLoginFields => EditKindIndex is 0 or 4;

    public bool ShowAliasFields => EditKindIndex == 1;

    public bool ShowMailboxPicker => EditKindIndex is 0 or 1;

    public bool ShowCardFields => EditKindIndex == 2;

    public bool ShowNoteFields => EditKindIndex == 3;

    public bool ShowIdentityFields => EditKindIndex == 4;

    public bool ShowRecoveryFields => EditKindIndex == 5;

    public bool ShowWifiFields => EditKindIndex == 6;

    public bool ShowSecretFields => EditKindIndex == 7;

    public bool ShowPasswordField => EditKindIndex is 0 or 4 or 6 or 7;

    public bool ShowPasswordHistory => ShowPasswordField;

    public string NameHeader => EditKindIndex switch
    {
        5 => UiStrings.Get("KindRecoveryLong"),
        6 => UiStrings.Get("WifiSsid"),
        7 => UiStrings.Get("KindSecretLong"),
        _ => UiStrings.Get("Name")
    };

    public string NamePlaceholderText => EditKindIndex switch
    {
        5 => UiStrings.Get("NamePlaceholderRecovery"),
        6 => UiStrings.Get("NamePlaceholderWifi"),
        7 => UiStrings.Get("NamePlaceholderSecret"),
        _ => UiStrings.Get("NamePlaceholder")
    };

    public string PasswordFieldHeader => EditKindIndex switch
    {
        6 => UiStrings.Get("PasswordFieldWifi"),
        7 => UiStrings.Get("PasswordFieldSecret"),
        _ => UiStrings.Get("Password")
    };

    public string NotesHeader => EditKindIndex switch
    {
        5 => UiStrings.Get("NotesHeaderRecovery"),
        7 => UiStrings.Get("NotesHeaderSecret"),
        _ => UiStrings.Get("Notes")
    };

    public int EditWifiSecurityIndex
    {
        get => _editWifiSecurityIndex;
        set
        {
            if (SetProperty(ref _editWifiSecurityIndex, value))
            {
                NotifySaveCommand();
                DebounceWifiQr();
            }
        }
    }

    public string WifiSecurityValue => EditWifiSecurityIndex switch
    {
        1 => WifiQr.Wep,
        2 => WifiQr.Open,
        _ => WifiQr.Wpa
    };

    public BitmapImage? WifiQrImage
    {
        get => _wifiQrImage;
        private set
        {
            if (SetProperty(ref _wifiQrImage, value))
            {
                OnPropertyChanged(nameof(HasWifiQr));
            }
        }
    }

    public bool HasWifiQr => WifiQrImage is not null;

    public string EditorIdenticonSeed => LocalIdenticon.SeedFor(KindFromIndex(EditKindIndex), EditUrl, EditTitle);

    public string EditTitle { get => _editTitle; set { if (SetProperty(ref _editTitle, value)) { NotifySaveCommand(); OnPropertyChanged(nameof(EditorIdenticonSeed)); DebounceWifiQr(); } } }
    public string EditUrl { get => _editUrl; set { if (SetProperty(ref _editUrl, value)) OnPropertyChanged(nameof(EditorIdenticonSeed)); } }

    public string EditBrowserContainer
    {
        get => _editBrowserContainer;
        private         set
        {
            SetProperty(ref _editBrowserContainer, BrowserContainerRules.Normalize(value));
        }
    }
    public string EditUsername
    {
        get => _editUsername;
        set
        {
            if (SetProperty(ref _editUsername, value))
            {
                _copyUsernameCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public string EditPassword
    {
        get => _editPassword;
        set
        {
            if (SetProperty(ref _editPassword, value))
            {
                _copyPasswordCommand.NotifyCanExecuteChanged();
                NotifySaveCommand();
                DebounceWifiQr();
            }
        }
    }

    public string EditNotes { get => _editNotes; set { if (SetProperty(ref _editNotes, value)) NotifySaveCommand(); } }
    public string EditTotpSecret
    {
        get => _editTotpSecret;
        set
        {
            if (SetProperty(ref _editTotpSecret, value))
            {
                DebounceTotpRestart();
            }
        }
    }

    public string TotpCode
    {
        get => _totpCode;
        private set
        {
            if (SetProperty(ref _totpCode, value))
            {
                CopyTotpCommand.NotifyCanExecuteChanged();
                OnPropertyChanged(nameof(TotpDisplay));
            }
        }
    }

    public int TotpSecondsLeft
    {
        get => _totpSecondsLeft;
        private set
        {
            if (SetProperty(ref _totpSecondsLeft, value))
            {
                OnPropertyChanged(nameof(TotpDisplay));
            }
        }
    }
    public string EditAliasEmail
    {
        get => _editAliasEmail;
        set
        {
            if (SetProperty(ref _editAliasEmail, value))
            {
                CopyAliasCommand.NotifyCanExecuteChanged();
                ComposeAliasCommand.NotifyCanExecuteChanged();
                NotifySaveCommand();
            }
        }
    }

    public string EditMailbox { get => _editMailbox; set => SetProperty(ref _editMailbox, value); }
    public string EditCardholder { get => _editCardholder; set => SetProperty(ref _editCardholder, value); }
    public string EditCardNumber { get => _editCardNumber; set { if (SetProperty(ref _editCardNumber, value)) NotifySaveCommand(); } }
    public string EditCardExpiry { get => _editCardExpiry; set => SetProperty(ref _editCardExpiry, value); }
    public string EditCardCvv { get => _editCardCvv; set => SetProperty(ref _editCardCvv, value); }
    public string EditFullName { get => _editFullName; set => SetProperty(ref _editFullName, value); }
    public string EditPhone { get => _editPhone; set => SetProperty(ref _editPhone, value); }
    public string EditAddress { get => _editAddress; set => SetProperty(ref _editAddress, value); }
    public string PrimaryEmail { get => _primaryEmail; set => SetProperty(ref _primaryEmail, value); }
    public string AliasDomain { get => _aliasDomain; set => SetProperty(ref _aliasDomain, value); }
    public string MailboxesText { get => _mailboxesText; set => SetProperty(ref _mailboxesText, value); }
    public string TotpDisplay => string.IsNullOrEmpty(TotpCode) ? UiStrings.Get("NoAuthenticator") : $"{TotpCode}   {TotpSecondsLeft}s";
    public string PasswordRevealLabel => IsPasswordVisible ? UiStrings.Get("Hide") : UiStrings.Get("Show");
    public string HealthSummary => HealthFindings.Count == 0
        ? UiStrings.Get("HealthNone")
        : UiStrings.Format("HealthCount", HealthFindings.Count);

    public string ClockStatus => _clockConfirmed
        ? UiStrings.Get("ClockConfirmed")
        : UiStrings.Get("ClockLocalOnly");

    public string UsageLine { get; private set; } = string.Empty;

    public string PasswordAgeWarning { get; private set; } = string.Empty;

    public bool HasPasswordAgeWarning => !string.IsNullOrWhiteSpace(PasswordAgeWarning);

    private DateTimeOffset TrustedUtc => TrustedClock.Bound(
        DateTimeOffset.UtcNow,
        _remoteSamples,
        _store.IsUnlocked ? _store.Settings.ClockFloorUtc : null);

    public bool MasterRotationOverdue =>
        IsUnlocked && !IsDecoySession && _store.Settings.MasterChangedUtc is { } changed
        && MasterPasswordPolicy.IsOverdue(changed, TrustedUtc);

    public bool MasterRotationSoon =>
        IsUnlocked && !IsDecoySession && _store.Settings.MasterChangedUtc is { } changed
        && MasterPasswordPolicy.IsWarning(changed, TrustedUtc);

    public string MasterRotationStatus
    {
        get
        {
            if (!IsUnlocked || IsDecoySession || _store.Settings.MasterChangedUtc is not { } changed)
            {
                return UiStrings.Get("MasterRotationHow");
            }

            if (MasterPasswordPolicy.IsOverdue(changed, TrustedUtc))
            {
                return UiStrings.Get("MasterRotationStatusOverdue");
            }

            var remaining = MasterPasswordPolicy.DaysRemaining(changed, TrustedUtc);
            if (MasterPasswordPolicy.IsWarning(changed, TrustedUtc))
            {
                return UiStrings.Format("MasterRotationSoon", remaining);
            }

            return UiStrings.Format(
                "MasterRotationOk",
                changed.ToLocalTime().ToString("yyyy-MM-dd"),
                remaining);
        }
    }

    public string AutofillHint => UiStrings.Get("AutofillHint");

    public string NewPersonName
    {
        get => _newPersonName;
        set
        {
            if (SetProperty(ref _newPersonName, value))
            {
                AddPersonCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public string NewMailboxLabel { get => _newMailboxLabel; set => SetProperty(ref _newMailboxLabel, value); }

    public string NewMailboxEmail
    {
        get => _newMailboxEmail;
        set
        {
            if (SetProperty(ref _newMailboxEmail, value))
            {
                AddMailboxCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public VaultOccupant? SelectedOccupant
    {
        get => _selectedOccupant;
        set
        {
            if (_loadingOccupants)
            {
                return;
            }

            if (value is not null && _selectedOccupant is not null && _selectedOccupant.Id == value.Id)
            {
                return;
            }

            var previous = _selectedOccupant;
            if (!SetProperty(ref _selectedOccupant, value) || value is null)
            {
                return;
            }

            OnPropertyChanged(nameof(CurrentPersonLabel));
            SwitchPersonCommand.NotifyCanExecuteChanged();
            _ = SwitchSelectedPersonAsync(previous);
        }
    }

    public MailboxProfile? SelectedMailboxProfile
    {
        get => _selectedMailboxProfile;
        set
        {
            if (_loadingMailboxes)
            {
                return;
            }

            if (!SetProperty(ref _selectedMailboxProfile, value))
            {
                return;
            }

            if (value is null)
            {
                RemoveMailboxCommand.NotifyCanExecuteChanged();
                MakeDefaultMailboxCommand.NotifyCanExecuteChanged();
                return;
            }

            EditMailbox = value.DisplayLabel;
            if (string.IsNullOrWhiteSpace(EditUsername) && ShowLoginFields)
            {
                EditUsername = value.Email;
            }

            RemoveMailboxCommand.NotifyCanExecuteChanged();
            MakeDefaultMailboxCommand.NotifyCanExecuteChanged();
        }
    }

    public string CurrentPersonLabel => SelectedOccupant?.DisplayName ?? UiStrings.Get("NoPerson");

    public bool HasSeveralPeople => Occupants.Count > 1;

    public string PeopleWarning => Occupants.Count > 1
        ? SharedPcGuidance.NamesAreVisible + " " + SharedPcGuidance.SharedWindowsAccount
        : SharedPcGuidance.SharedWindowsAccount;

    public string HelloWarning => SharedPcGuidance.HelloCannotTellPeopleApart;

    public string MailboxWarning => SharedPcGuidance.MailboxProfilesStayInside;

    public string SwitchWarning => SharedPcGuidance.SwitchLocksMemory;

    public string PanicWarning => SharedPcGuidance.PanicIsNotForensics;

    public bool DecoyExists
    {
        get => _decoyExists;
        private set
        {
            if (SetProperty(ref _decoyExists, value))
            {
                NotifyPanicCommands();
                OnPropertyChanged(nameof(DecoyStatusText));
            }
        }
    }

    public bool IsDecoySession
    {
        get => _isDecoySession;
        private set
        {
            if (SetProperty(ref _isDecoySession, value))
            {
                OnPropertyChanged(nameof(IsPanicDecoySession));
                OnPropertyChanged(nameof(ShowDecoyBanner));
                NotifyPanicCommands();
                NotifyPersonCommands();
                CreateShamirCommand.NotifyCanExecuteChanged();
                NotifyUsbCommands();
            }
        }
    }

    public bool IsEditingDecoy
    {
        get => _isEditingDecoy;
        private set
        {
            if (SetProperty(ref _isEditingDecoy, value))
            {
                OnPropertyChanged(nameof(IsPanicDecoySession));
                OnPropertyChanged(nameof(ShowDecoyBanner));
                DoneEditingDecoyCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public bool IsPanicDecoySession => IsDecoySession && !IsEditingDecoy;

    public bool ShowDecoyBanner => IsEditingDecoy;

    public string DecoyStatusText => DecoyExists ? UiStrings.Get("DecoyReady") : UiStrings.Get("NoDecoyYet");

    public bool OpenDecoyOnPanic
    {
        get => _preferences.LoadOpenDecoyOnPanic();
        set
        {
            if (OpenDecoyOnPanic == value)
            {
                return;
            }

            _preferences.SaveOpenDecoyOnPanic(value);
            OnPropertyChanged();
        }
    }

    public async Task InitializeAsync()
    {
        await _occupants.LoadAsync();
        RefreshOccupantList();
        var active = _occupants.Active();
        if (active is null)
        {
            SelectOccupantQuietly(null);
            NeedsSetup = true;
            IsLocked = true;
            ApplyDefaultPersonName();
            SetStatus("SetupFirstStatus");
            await RefreshDecoyExistsAsync();
            return;
        }

        await ApplyOccupantAsync(active, lockVault: true);
        await RefreshDecoyExistsAsync();
    }

    public async Task SaveGeneratedAsync(string password, string? title = null, string? url = null, string? username = null)
    {
        if (!IsUnlocked)
        {
            QueueGeneratedLogin(password, title, url, username);
            return;
        }

        ApplyLogin(password, title, url, username);
        await SaveItemAsync();
    }

    public void QueueGeneratedLogin(string password, string? title = null, string? url = null, string? username = null)
    {
        _pendingLogin = new PendingLogin(
            password,
            string.IsNullOrWhiteSpace(title) ? UiStrings.Get("NewLoginTitle") : title.Trim(),
            url?.Trim() ?? string.Empty,
            username?.Trim() ?? string.Empty);

        SetStatus(NeedsSetup ? "QueueNeedsSetup" : "QueueNeedsUnlock");
    }

    public (string Username, string Password) GetAutofillCredentials()
    {
        if (!IsUnlocked)
        {
            return (string.Empty, string.Empty);
        }

        NoteUsed(method: AuditMethod.Autofill);
        return (VaultItemRules.AutofillUsername(EditAliasEmail, EditUsername), EditPassword);
    }

    public bool TryGetFillCredentials(string hint, out string username, out string password)
    {
        username = string.Empty;
        password = string.Empty;
        if (!IsUnlocked)
        {
            return false;
        }

        var item = SiteMatchService.BestMatchForHint(_store.Items, hint)
            ?? (_editingId != Guid.Empty ? _store.Find(_editingId) : null);
        if (item is not null)
        {
            username = VaultItemRules.AutofillUsername(item.AliasEmail, item.Username);
            password = item.Password;
            NoteUsed(item.Id, AuditMethod.Autofill);
        }
        else
        {
            username = VaultItemRules.AutofillUsername(EditAliasEmail, EditUsername);
            password = EditPassword;
        }

        return !string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password);
    }

    public async Task SealDroppedFileAsync(string fileName, byte[] data, bool offerPortableCopy = true)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (!VaultItemRules.IsAllowedAttachmentSize(data.Length) && !VaultItemRules.IsSealedBlob(data))
        {
            SetStatus("FileTooLarge", Path.GetFileName(fileName), VaultItemRules.MaximumAttachmentBytes / (1024 * 1024));
            CryptographicOperations.ZeroMemory(data);
            return;
        }

        if (NeedsSetup)
        {
            QueuePendingSeal(fileName, data);
            CryptographicOperations.ZeroMemory(data);
            VaultPageRequested?.Invoke();
            SetStatus("SetupToSeal");
            return;
        }

        if (!IsUnlocked)
        {
            QueuePendingSeal(fileName, data);
            CryptographicOperations.ZeroMemory(data);
            VaultPageRequested?.Invoke();
            SetStatus("UnlockToSeal");
            return;
        }

        try
        {
            if (VaultItemRules.IsSealedBlob(data))
            {
                await ImportSealedBlobAsync(data);
                return;
            }

            await SealPlainFileAsync(fileName, data, offerPortableCopy);
        }
        catch (Exception)
        {
            SetStatus("CouldNotSeal");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    public StudentVaultInsight InspectGeneratedSecret(string secret, string? siteUrl)
    {
        return StudentModeExplainer.Inspect(IsUnlocked ? _store.Items : null, secret, siteUrl);
    }

    private async Task ContinueAfterBindAsync(byte[] bind, bool allowHourSkip)
    {
        if (allowHourSkip && HumanPresenceSkipRules.AllowsSkip(_humanSkipLast, DateTimeOffset.UtcNow))
        {
            await FinishUnlockFromBindAsync(bind).ConfigureAwait(true);
            return;
        }

        BeginHumanVerification(bind);
        SetStatus("HumanVerificationHint");
    }

    private async Task FinishUnlockFromBindAsync(byte[] bind)
    {
        HumanPresenceReceipt? receipt = null;
        try
        {
            receipt = HumanPresenceReceipt.ForBind(bind);
            CryptographicOperations.ZeroMemory(bind);
            await _store.RevealAfterHumanAsync(receipt).ConfigureAwait(true);
            receipt = null;
            await CompleteHumanUnlockAsync().ConfigureAwait(true);
        }
        catch (Exception)
        {
            receipt?.Dispose();
            CryptographicOperations.ZeroMemory(bind);
            await RecordLockedFailAsync(AuditMethod.Human).ConfigureAwait(true);
            Lock("HumanVerificationFailed");
        }
    }

    private async Task CompleteHumanUnlockAsync()
    {
        var cont = _afterHuman;
        _afterHuman = null;
        ClearHumanVerification();
        IsLocked = false;
        OnPropertyChanged(nameof(IsUnlocked));
        RememberHumanSkip();
        if (cont is not null)
        {
            await cont().ConfigureAwait(true);
            return;
        }

        await AfterUnlockAsync().ConfigureAwait(true);
    }

    private void RememberHumanSkip()
    {
        if (IsDecoySession || IsEditingDecoy)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        _humanSkipLast = now;
        HumanPresenceSkipFile.Write(now);
    }

    private void ClearHumanSkip()
    {
        _humanSkipLast = null;
        HumanPresenceSkipFile.Clear();
    }

    private void BeginHumanVerification(byte[] bind)
    {
        ClearHumanVerification(keepPending: false);
        _human = HumanPresenceChallenge.Start(bind);
        CryptographicOperations.ZeroMemory(bind);
        _isPendingHuman = true;
        _humanFailures = 0;
        PublishHumanUi();
        OnPropertyChanged(nameof(IsPendingHumanVerification));
        OnPropertyChanged(nameof(ShowUnlock));
        OnPropertyChanged(nameof(ShowHumanVerification));
        OnPropertyChanged(nameof(ShowWorkspace));
        OnPropertyChanged(nameof(IsUnlocked));
        OnPropertyChanged(nameof(HumanVerificationHeading));
        OnPropertyChanged(nameof(HumanVerificationDetail));
        CancelHumanVerificationCommand.NotifyCanExecuteChanged();
    }

    private async void SubmitHumanDigit(string? raw)
    {
        if (_human is null || !int.TryParse(raw, out var digit))
        {
            return;
        }

        var result = _human.SubmitDigit(digit);
        if (_factoryResetPending)
        {
            await HandleFactoryResetHumanAsync(result).ConfigureAwait(true);
            return;
        }

        if (result is HumanPresenceSubmitResult.Wrong)
        {
            _humanFailures++;
            PublishHumanUi();
            SetStatus("HumanVerificationWrong");
            if (_humanFailures >= 8)
            {
                await RecordLockedFailAsync(AuditMethod.Human).ConfigureAwait(true);
                Lock("TooManyAttempts");
                return;
            }

            if (_humanFailures >= 3)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(300 * Math.Min(_humanFailures - 2, 5))).ConfigureAwait(true);
            }

            return;
        }

        if (result is HumanPresenceSubmitResult.Expired or HumanPresenceSubmitResult.Consumed or HumanPresenceSubmitResult.Invalid)
        {
            await RecordLockedFailAsync(AuditMethod.Human).ConfigureAwait(true);
            Lock("HumanVerificationExpired");
            return;
        }

        PublishHumanUi();
        if (result != HumanPresenceSubmitResult.Completed || !_human.TryConsume(out var receipt))
        {
            return;
        }

        try
        {
            await _store.RevealAfterHumanAsync(receipt).ConfigureAwait(true);
        }
        catch (Exception)
        {
            await RecordLockedFailAsync(AuditMethod.Human).ConfigureAwait(true);
            Lock("HumanVerificationFailed");
            return;
        }

        await CompleteHumanUnlockAsync().ConfigureAwait(true);
    }

    private void CancelHumanVerification()
    {
        if (_factoryResetPending)
        {
            AbortFactoryReset("ResetAppCancelled");
            return;
        }

        Lock("LockedDefault");
    }

    private void PublishHumanUi()
    {
        _humanDisplay = _human?.DisplayText ?? string.Empty;
        HumanKeypad.Clear();
        if (_human is not null)
        {
            foreach (var key in _human.Keypad)
            {
                HumanKeypad.Add(key.ToString());
            }
        }

        OnPropertyChanged(nameof(HumanChallengeText));
    }

    private void ClearHumanVerification(bool keepPending = false)
    {
        _human?.Dispose();
        _human = null;
        _humanDisplay = string.Empty;
        HumanKeypad.Clear();
        if (!keepPending)
        {
            _isPendingHuman = false;
            _afterHuman = null;
        }

        OnPropertyChanged(nameof(HumanChallengeText));
        OnPropertyChanged(nameof(IsPendingHumanVerification));
        OnPropertyChanged(nameof(ShowUnlock));
        OnPropertyChanged(nameof(ShowHumanVerification));
        OnPropertyChanged(nameof(ShowWorkspace));
        CancelHumanVerificationCommand.NotifyCanExecuteChanged();
    }

    public void PressMasterKey(string? id)
    {
        var outcome = _masterKeyboard.Handle(id);
        if (outcome.Backspace)
        {
            MasterBackspace();
        }
        else if (!string.IsNullOrEmpty(outcome.Insert))
        {
            MasterPassword += outcome.Insert;
        }

        if (outcome.LayoutChanged)
        {
            NotifyMasterKeyboard();
        }
    }

    private void NotifyMasterKeyboard()
    {
        MasterKeyboardRevision++;
        OnPropertyChanged(nameof(MasterKeyboardRevision));
        OnPropertyChanged(nameof(MasterKeyboardRows));
    }

    private void MasterBackspace()
    {
        if (MasterPassword.Length == 0)
        {
            return;
        }

        MasterPassword = MasterPassword[..^1];
    }

    private async Task CreateVaultAsync()
    {
        ClearStatus();
        if (!VaultCryptography.FixedEquals(MasterPassword, ConfirmPassword))
        {
            SetStatus("PasswordsDoNotMatch");
            return;
        }

        IsBusy = true;
        try
        {
            if (SelectedOccupant is null)
            {
                var created = await _occupants.AddAsync(string.IsNullOrWhiteSpace(NewPersonName) ? UiStrings.Get("MyVault") : NewPersonName);
                RefreshOccupantList();
                SelectOccupantQuietly(created);
            }

            if (SelectedOccupant is null)
            {
                SetStatus("ChoosePerson");
                return;
            }

            _store.SelectFolder(SelectedOccupant.FolderName);
            if (await _store.ExistsAsync())
            {
                NeedsSetup = false;
                IsLocked = true;
                SetStatus("AlreadyHasVault");
                return;
            }

            _unlockMethod = AuditMethod.Master;
            var bind = await _store.CreateAsync(MasterPassword);
            NeedsSetup = false;
            IsLocked = true;
            _failedUnlocks = 0;
            var person = CurrentPersonLabel;
            var masterForPhrase = MasterPassword;
            ClearMasterFields();
            _afterHuman = async () =>
            {
                if (SelectedOccupant is not null)
                {
                    await _occupants.TouchAsync(SelectedOccupant.Id);
                }

                await IssueRecoveryPhraseOnceAsync(masterForPhrase).ConfigureAwait(true);
                await TryEnableHelloForRecoveryAsync().ConfigureAwait(true);
                await AfterUnlockAsync().ConfigureAwait(true);
                SetStatus("VaultCreated", person);
            };
            BeginHumanVerification(bind);
            SetStatus("HumanVerificationHint");
        }
        catch (ArgumentException exception)
        {
            SetStatusRaw(exception.Message);
        }
        catch (Exception)
        {
            SetStatus("CouldNotCreateVault");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task UnlockAsync()
    {
        ClearStatus();
        if (DateTimeOffset.UtcNow < _nextUnlockAllowed)
        {
            SetStatus("TooManyAttempts");
            return;
        }

        IsBusy = true;
        try
        {
            _unlockMethod = AuditMethod.Master;
            var bind = await _store.AuthenticateMasterAsync(MasterPassword);
            ClearMasterFields();
            await ContinueAfterBindAsync(bind, allowHourSkip: true).ConfigureAwait(true);
        }
        catch (CryptographicException)
        {
            _failedUnlocks++;
            var delaySeconds = Math.Min(32, 1 << Math.Min(_failedUnlocks, 5));
            _nextUnlockAllowed = DateTimeOffset.UtcNow.AddSeconds(delaySeconds);
            await RecordLockedFailAsync(AuditMethod.Master);
            await Task.Delay(TimeSpan.FromSeconds(Math.Min(delaySeconds, 4)));
            SetStatus("WrongMaster");
        }
        catch (Exception)
        {
            SetStatus("CouldNotOpen");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task UnlockWithHelloAsync()
    {
        IsBusy = true;
        try
        {
            var availability = await UserConsentVerifier.CheckAvailabilityAsync();
            if (availability != UserConsentVerifierAvailability.Available)
            {
                SetStatus("HelloUnavailablePc");
                return;
            }

            var result = await UserConsentVerifier.RequestVerificationAsync(UiStrings.Get("UnlockStemVault"));
            if (result != UserConsentVerificationResult.Verified)
            {
                await RecordLockedFailAsync(AuditMethod.HelloCancel).ConfigureAwait(true);
                SetStatus("HelloCancelled");
                return;
            }

            var key = await _store.LoadHelloKeyAsync();
            var bind = await _store.AuthenticateWithKeyAsync(key);
            _unlockMethod = AuditMethod.Hello;
            await ContinueAfterBindAsync(bind, allowHourSkip: true).ConfigureAwait(true);
        }
        catch (Exception)
        {
            await RecordLockedFailAsync(AuditMethod.Hello).ConfigureAwait(true);
            SetStatus("HelloFailed");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task AfterUnlockAsync()
    {
        if (!_store.IsUnlocked)
        {
            Lock("CouldNotOpen");
            return;
        }

        ClearHumanVerification();
        IsLocked = false;
        _failedUnlocks = 0;
        ClearMasterFields();
        LoadSettings();
        await RefreshTrustedTimeAsync().ConfigureAwait(true);
        if (!IsDecoySession)
        {
            await _store.AbsorbPendingFailuresAsync().ConfigureAwait(true);
            _store.AppendAudit(AuditKind.UnlockOk, _unlockMethod, utc: TrustedUtc);
            await _store.SaveAsync().ConfigureAwait(true);
            await _store.DiscardPendingFailuresAsync().ConfigureAwait(true);
        }

        HelloAvailable = IsDecoySession ? false : await _store.HelloEnabledAsync();
        UsbUnlockAvailable = IsDecoySession ? false : await _store.UsbUnlockEnabledAsync();
        RecoveryConfigured = IsDecoySession ? false : await _store.RecoveryConfiguredAsync();
        if (!IsDecoySession && SelectedOccupant is not null)
        {
            await _occupants.TouchAsync(SelectedOccupant.Id);
        }

        RefreshVisibleItems();
        _ = RefreshHealthAsync();
        if (IsDecoySession)
        {
            if (VisibleItems.Count > 0)
            {
                SelectedItem = VisibleItems[0];
            }
            else
            {
                NewItem(VaultItemKind.Login);
            }

            if (IsEditingDecoy)
            {
                SetStatus("EditingDecoyBody");
            }
            else
            {
                SetStatus("EncryptedItems", _store.Items.Count);
            }

            return;
        }

        var consumedPending = await TryConsumePendingAsync() || await TryConsumePendingSealsAsync();
        if (!consumedPending)
        {
            if (VisibleItems.Count > 0)
            {
                SelectedItem = VisibleItems[0];
            }
            else
            {
                NewItem(VaultItemKind.Login);
            }
        }

        await _store.EnsureMasterRotationStampAsync(TrustedUtc).ConfigureAwait(true);
        RefreshMasterRotation();
        if (MasterRotationOverdue)
        {
            SetStatus("MasterRotationDue");
            await ChangeMasterAsync(required: true).ConfigureAwait(true);
            await OfferMissingRecoveryKitAsync().ConfigureAwait(true);
            return;
        }

        if (MasterRotationSoon && _store.Settings.MasterChangedUtc is { } warningStamp)
        {
            SetStatus("MasterRotationSoon", MasterPasswordPolicy.DaysRemaining(warningStamp, TrustedUtc));
        }
        else if (!consumedPending)
        {
            SetStatus("EncryptedItems", _store.Items.Count);
        }

        await OfferMissingRecoveryKitAsync().ConfigureAwait(true);
    }

    public void Lock(string? messageKey = null)
    {
        if (_factoryResetPending && !_wipingAppData)
        {
            _factoryResetPending = false;
            OnPropertyChanged(nameof(HumanVerificationHeading));
            OnPropertyChanged(nameof(HumanVerificationDetail));
        }

        var restoreHome = _isDecoySession;
        CancelPasswordHide();
        StopTotpLoop();
        _searchDebounceCancellation?.Cancel();
        _wifiQrDebounceCancellation?.Cancel();
        _totpDebounceCancellation?.Cancel();
        _healthGeneration++;
        _store.Lock();
        ClearHumanVerification();
        ClearMailboxState();
        IsDecoySession = false;
        IsEditingDecoy = false;
        IsLocked = true;
        VisibleItems.Clear();
        VisibleMedia.Clear();
        _mediaThumbs.Clear();
        _mediaThumbGeneration++;
        _selectedMedia = null;
        OnPropertyChanged(nameof(SelectedMedia));
        VisibleAudit.Clear();
        SelectedAudit = null;
        FolderFilters.Clear();
        FolderSuggestions.Clear();
        _selectedFolderFilter = null;
        HealthFindings.Clear();
        OnPropertyChanged(nameof(HealthSummary));
        RefreshMasterRotation();
        AttachmentNames.Clear();
        WifiQrImage = null;
        _wifiQrGeneration++;
        BindPasswordHistory(null);
        ClearEditor();
        ClearMediaPreview();
        if (_isMediaSection || _isAuditSection)
        {
            _isMediaSection = false;
            _isAuditSection = false;
            OnPropertyChanged(nameof(IsMediaSection));
            OnPropertyChanged(nameof(IsAuditSection));
            NotifyWorkspace();
        }
        _pendingLogin = null;
        ClearPendingSeals();
        if (_searchQuery.Length > 0)
        {
            _searchQuery = string.Empty;
            OnPropertyChanged(nameof(SearchQuery));
        }

        if (restoreHome)
        {
            _store.SelectFolder(_homeFolderName);
            _ = RestoreHomeProbeAsync();
        }

        SetStatus(string.IsNullOrWhiteSpace(messageKey) ? "LockedDefault" : messageKey);
    }

    private async Task<bool> TryConsumePendingAsync()
    {
        if (_pendingLogin is null)
        {
            return false;
        }

        var pending = _pendingLogin;
        _pendingLogin = null;
        ApplyLogin(pending.Password, pending.Title, pending.Url, pending.Username);
        await SaveItemAsync();
        return true;
    }

    private async Task<bool> TryConsumePendingSealsAsync()
    {
        if (_pendingSeals.Count == 0)
        {
            return false;
        }

        var pending = _pendingSeals.ToArray();
        _pendingSeals.Clear();
        foreach (var seal in pending)
        {
            await SealDroppedFileAsync(seal.Name, seal.Data, offerPortableCopy: pending.Length == 1);
        }

        return true;
    }

    private void QueuePendingSeal(string fileName, byte[] data)
    {
        _pendingSeals.Add(new PendingSeal(fileName, data.ToArray()));
    }

    private void ClearPendingSeals()
    {
        foreach (var seal in _pendingSeals)
        {
            CryptographicOperations.ZeroMemory(seal.Data);
        }

        _pendingSeals.Clear();
    }

    private async Task SealPlainFileAsync(string fileName, byte[] data, bool offerPortableCopy)
    {
        var item = SealedFileFactory.CreateNote(fileName, data, UiStrings.Get("SealedNoteLabel"));
        item = _store.Add(item);
        NoteAudit(AuditKind.Created, string.Empty, item.Title, item.Kind, item.Id);
        await _store.SaveAsync();
        ShowItemsWorkspace();
        LoadEditor(item);
        RefreshVisibleItems();
        _ = RefreshHealthAsync();
        VaultPageRequested?.Invoke();
        SetStatus("FileSealed", item.Title, CurrentPersonLabel);

        if (!offerPortableCopy || SaveFileRequested is null || ConfirmAsync is null)
        {
            return;
        }

        var saveCopy = await ConfirmAsync(
            UiStrings.Get("SaveSpgFileTitle"),
            UiStrings.Get("SaveSpgFileBody") + " " + SharedPcGuidance.SharedWindowsAccount,
            UiStrings.Get("SaveSpgFile"));
        if (!saveCopy)
        {
            return;
        }

        var blob = _store.ExportWithSessionKey([item.Id]);
        try
        {
            var portableName = Path.ChangeExtension(item.Title, ".spgfile");
            if (string.IsNullOrWhiteSpace(Path.GetFileNameWithoutExtension(portableName)))
            {
                portableName = "sealed.spgfile";
            }

            await SaveFileRequested.Invoke(portableName, blob);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(blob);
        }
    }

    private async Task ImportSealedBlobAsync(byte[] data)
    {
        VaultPageRequested?.Invoke();
        if (_store.TryImportWithSessionKey(data, out var added))
        {
            await _store.SaveAsync();
            NoteAudit(AuditKind.Imported, string.Empty, added.ToString());
            await _store.SaveAsync();
            RefreshVisibleItems();
            _ = RefreshHealthAsync();
            SetStatus("ImportedSealed", added);
            return;
        }

        if (AskSharePasswordAsync is null)
        {
            SetStatus("CouldNotImportSealed");
            return;
        }

        var password = await AskSharePasswordAsync(UiStrings.Get("ImportShareTitle"));
        if (password is null)
        {
            return;
        }

        added = _store.ImportShare(data, password);
        NoteAudit(AuditKind.Imported, string.Empty, added.ToString());
        await _store.SaveAsync();
        RefreshVisibleItems();
        _ = RefreshHealthAsync();
        SetStatus("ImportedItems", added);
    }

    private void ApplyLogin(string password, string? title, string? url, string? username)
    {
        NewItem(VaultItemKind.Login);
        ShowItemsWorkspace();
        EditPassword = password;
        EditTitle = string.IsNullOrWhiteSpace(title) ? UiStrings.Get("NewLoginTitle") : title.Trim();
        EditUrl = url?.Trim() ?? string.Empty;
        EditUsername = username ?? string.Empty;
        IsPasswordVisible = true;
    }

    private void NewItem(string kind)
    {
        _selected = null;
        OnPropertyChanged(nameof(SelectedItem));
        _editingId = Guid.Empty;
        _pendingBrowserContainer = string.Empty;
        EditKindIndex = KindIndex(kind);
        EditTitle = string.Empty;
        EditUrl = string.Empty;
        EditBrowserContainer = string.Empty;
        EditUsername = string.Empty;
        EditPassword = string.Empty;
        EditNotes = string.Empty;
        EditTotpSecret = string.Empty;
        EditAliasEmail = string.Empty;
        EditMailbox = string.Empty;
        EditCardholder = string.Empty;
        EditCardNumber = string.Empty;
        EditCardExpiry = string.Empty;
        EditCardCvv = string.Empty;
        EditFullName = string.Empty;
        EditPhone = string.Empty;
        EditAddress = string.Empty;
        EditWifiSecurityIndex = 0;
        EditFolder = FolderForNewItem();
        AttachmentNames.Clear();
        BindPasswordHistory(null);
        IsPasswordVisible = true;
        RefreshUsageLabels();
        SelectedMailboxProfile = MailboxProfileService.Default(MailboxProfiles);
        NotifyEditorCommands();
    }

    private void LoadEditor(VaultItem item)
    {
        _editingId = item.Id;
        EditKindIndex = KindIndex(item.Kind);
        EditTitle = item.Title;
        EditUrl = item.Url;
        EditBrowserContainer = item.BrowserContainer;
        EditUsername = item.Username;
        EditPassword = item.Password;
        EditNotes = item.Notes;
        EditTotpSecret = item.TotpSecret;
        EditAliasEmail = item.AliasEmail;
        EditMailbox = item.Mailbox;
        EditCardholder = item.Cardholder;
        EditCardNumber = item.CardNumber;
        EditCardExpiry = item.CardExpiry;
        EditCardCvv = item.CardCvv;
        EditFullName = item.FullName;
        EditPhone = item.Phone;
        EditAddress = item.Address;
        EditFolder = item.Folder;
        EditWifiSecurityIndex = WifiQr.NormalizeSecurity(item.WifiSecurity) switch
        {
            WifiQr.Wep => 1,
            WifiQr.Open => 2,
            _ => 0
        };
        AttachmentNames.Clear();
        foreach (var file in item.Attachments)
        {
            AttachmentNames.Add($"{file.FileName} ({file.Data.Length} bytes)");
        }

        BindPasswordHistory(item.PasswordHistory);
        IsPasswordVisible = false;
        RefreshUsageLabels();
        SelectedMailboxProfile = MailboxProfiles.FirstOrDefault(profile =>
                profile.DisplayLabel.Equals(item.Mailbox, StringComparison.OrdinalIgnoreCase)
                || profile.Label.Equals(item.Mailbox, StringComparison.OrdinalIgnoreCase)
                || profile.Email.Equals(item.Username, StringComparison.OrdinalIgnoreCase))
            ?? MailboxProfileService.Default(MailboxProfiles);
        NotifyEditorCommands();
    }

    private async Task SaveItemAsync()
    {
        if (IsMediaSection)
        {
            await SaveMediaTitleAsync();
            return;
        }
        if (!CanSaveItem())
        {
            _pendingBrowserContainer = string.Empty;
            return;
        }

        var parsedSecret = TotpService.TryParseOtpAuth(EditTotpSecret);
        var totp = parsedSecret ?? EditTotpSecret.Trim();
        var existing = _editingId == Guid.Empty ? null : _store.Find(_editingId);
        var rotated = existing is not null
            && !string.IsNullOrEmpty(existing.Password)
            && !string.Equals(existing.Password, EditPassword, StringComparison.Ordinal);
        var history = PasswordHistoryRules.ForSave(existing, EditPassword, TrustedUtc);
        var now = TrustedUtc;
        var browserContainer = string.IsNullOrEmpty(_pendingBrowserContainer)
            ? BrowserContainerRules.Normalize(EditBrowserContainer)
            : _pendingBrowserContainer;
        _pendingBrowserContainer = string.Empty;
        var item = new VaultItem
        {
            Id = _editingId == Guid.Empty ? Guid.NewGuid() : _editingId,
            Kind = KindFromIndex(EditKindIndex),
            Title = EditTitle.Trim(),
            Url = EditUrl.Trim(),
            Username = EditUsername.Trim(),
            Password = EditPassword,
            PasswordHistory = history,
            TotpSecret = totp,
            AliasEmail = EditAliasEmail.Trim(),
            Mailbox = EditMailbox.Trim(),
            Cardholder = EditCardholder.Trim(),
            CardNumber = EditCardNumber.Trim(),
            CardExpiry = EditCardExpiry.Trim(),
            CardCvv = EditCardCvv.Trim(),
            FullName = EditFullName.Trim(),
            Phone = EditPhone.Trim(),
            Address = EditAddress.Trim(),
            Folder = VaultOrganizer.Normalize(EditFolder),
            BrowserContainer = browserContainer,
            WifiSecurity = WifiSecurityValue,
            Notes = EditNotes.Trim(),
            Attachments = existing?.Attachments ?? [],
            CreatedUtc = existing?.CreatedUtc ?? now,
            ModifiedUtc = now,
            LastUsedUtc = existing?.LastUsedUtc,
            PasswordChangedUtc = rotated || existing is null
                ? now
                : existing.PasswordChangedUtc ?? existing.CreatedUtc
        };

        if (_editingId == Guid.Empty)
        {
            _store.Add(item);
            NoteAudit(AuditKind.Created, string.Empty, item.Title, item.Kind, item.Id);
        }
        else
        {
            _store.Update(item);
            NoteAudit(rotated ? AuditKind.PasswordChanged : AuditKind.Updated, string.Empty, item.Title, item.Kind, item.Id);
        }

        await _store.SaveAsync();
        _editingId = item.Id;
        EditBrowserContainer = item.BrowserContainer;
        RefreshVisibleItems();
        RefreshHealth();
        SelectedItem = VisibleItems.FirstOrDefault(entry => entry.Id == item.Id);
        BindPasswordHistory(item.PasswordHistory);
        RefreshUsageLabels();
        SetStatus(rotated ? "SavedPasswordRotated" : "SavedVault");
        NotifyEditorCommands();
    }

    private async Task DeleteItemAsync()
    {
        if (_editingId == Guid.Empty)
        {
            return;
        }

        if (IsMediaSection)
        {
            await DeleteMediaItemAsync();
            return;
        }

        if (ConfirmAsync is not null
            && !await ConfirmAsync(UiStrings.Get("DeleteItemTitle"), UiStrings.Get("DeleteItemBody"), UiStrings.Get("Delete")))
        {
            return;
        }

        var removing = _store.Find(_editingId);
        NoteAudit(AuditKind.Deleted, string.Empty, removing?.Title, removing?.Kind, _editingId);
        _store.Delete(_editingId);
        await _store.SaveAsync();
        RefreshVisibleItems();
        RefreshHealth();
        if (VisibleItems.Count > 0)
        {
            SelectedItem = VisibleItems[0];
        }
        else
        {
            NewItem(VaultItemKind.Login);
        }

        SetStatus("ItemRemoved");
    }

    private bool CanSaveItem()
    {
        return IsUnlocked && VaultItemRules.CanSave(
            KindFromIndex(EditKindIndex),
            EditTitle,
            EditPassword,
            EditAliasEmail,
            EditCardNumber,
            EditNotes,
            EditFullName,
            EditUsername,
            WifiSecurityValue);
    }

    private void RefreshVisibleItems()
    {
        var query = SearchQuery.Trim();
        var folderKey = _selectedFolderFilter?.Key ?? VaultOrganizer.AllKey;
        var next = new List<VaultListItem>();
        if (IsMediaSection)
        {
            var filtered = MediaGalleryRules.Sort(
                MediaGalleryRules.Filter(_store.Media, MediaGalleryCategory, folderKey, query),
                _mediaSortKey);
            var mediaRows = new List<MediaGalleryRow>(filtered.Count);
            for (var i = 0; i < filtered.Count; i++)
            {
                var item = filtered[i];
                next.Add(VaultListItem.From(item));
                var row = MediaGalleryRow.From(item);
                if (_mediaThumbs.TryGetValue(item.Id, out var thumb))
                {
                    row.Thumbnail = thumb;
                }

                mediaRows.Add(row);
            }

            ReplaceVisibleMedia(mediaRows);
            _ = LoadGalleryThumbnailsAsync(mediaRows);
        }
        else
        {
            var items = _store.Items;
            next.Capacity = items.Count;
            for (var i = 0; i < items.Count; i++)
            {
                var item = items[i];
                if (!VaultOrganizer.InFolder(item.Folder, folderKey))
                {
                    continue;
                }

                if (query.Length == 0 || Matches(item, query))
                {
                    next.Add(VaultListItem.From(item));
                }
            }
        }

        RebuildFolderUi();

        var selectedId = SelectedItem?.Id;
        ReplaceVisibleItems(next);
        if (IsMediaSection)
        {
            var match = selectedId is { } id
                ? VisibleItems.FirstOrDefault(entry => entry.Id == id)
                : null;
            SelectedItem = match ?? VisibleItems.FirstOrDefault();
        }
        else if (selectedId is { } id)
        {
            var match = VisibleItems.FirstOrDefault(entry => entry.Id == id);
            if (!ReferenceEquals(SelectedItem, match))
            {
                SelectedItem = match;
            }
        }

        if (IsAuditSection)
        {
            RefreshAudit();
        }
    }

    private void ShowItemsWorkspace()
    {
        IsAuditSection = false;
        IsMediaSection = false;
    }

    private void NotifyWorkspace()
    {
        OnPropertyChanged(nameof(ShowLoginSection));
        OnPropertyChanged(nameof(ShowMediaEditor));
        OnPropertyChanged(nameof(ShowMediaPhotoGallery));
        OnPropertyChanged(nameof(ShowMediaVideoGallery));
        OnPropertyChanged(nameof(ShowMediaAudioGallery));
        OnPropertyChanged(nameof(ShowMediaFileExplorer));
        OnPropertyChanged(nameof(ShowMediaCardGallery));
        OnPropertyChanged(nameof(ShowAuditSection));
        OnPropertyChanged(nameof(ShowFolderFilter));
        OnPropertyChanged(nameof(VaultWorkspaceTitle));
        OnPropertyChanged(nameof(FolderFilterHeader));
        OnPropertyChanged(nameof(MediaAddCurrentLabel));
        OnPropertyChanged(nameof(MediaGalleryTitle));
    }

    private void NoteAudit(string kind, string method, string? title = null, string? itemKind = null, Guid? itemId = null)
    {
        if (!IsUnlocked || IsDecoySession)
        {
            return;
        }

        _store.AppendAudit(kind, method, title, itemKind, itemId, TrustedUtc);
        if (IsAuditSection)
        {
            RefreshAudit();
        }
    }

    private async Task RecordLockedFailAsync(string method)
    {
        try
        {
            await _store.RecordLockedFailureAsync(TrustedUtc, method).ConfigureAwait(true);
        }
        catch (Exception)
        {
        }
    }

    private void RebuildAuditFilters()
    {
        _rebuildingAuditFilters = true;
        try
        {
            var previous = _selectedAuditFilter?.Key ?? AuditBucket.All;
            AuditFilters.Clear();
            AuditFilters.Add(new FolderFilterChoice(AuditBucket.All, UiStrings.Get("AuditFilterAll")));
            AuditFilters.Add(new FolderFilterChoice(AuditBucket.Fail, UiStrings.Get("AuditFilterFail")));
            AuditFilters.Add(new FolderFilterChoice(AuditBucket.Use, UiStrings.Get("AuditFilterUse")));
            AuditFilters.Add(new FolderFilterChoice(AuditBucket.Entry, UiStrings.Get("AuditFilterEntry")));
            _selectedAuditFilter = AuditFilters.FirstOrDefault(choice =>
                string.Equals(choice.Key, previous, StringComparison.Ordinal))
                ?? AuditFilters[0];
            OnPropertyChanged(nameof(SelectedAuditFilter));
        }
        finally
        {
            _rebuildingAuditFilters = false;
        }
    }

    private void RefreshAudit()
    {
        if (!IsUnlocked)
        {
            VisibleAudit.Clear();
            SelectedAudit = null;
            return;
        }

        var bucket = _selectedAuditFilter?.Key ?? AuditBucket.All;
        var query = SearchQuery.Trim();
        var next = new List<AuditRow>();
        var events = _store.Audit;
        for (var i = events.Count - 1; i >= 0; i--)
        {
            var item = events[i];
            if (!AuditRules.InBucket(item, bucket) || !AuditRules.Matches(item, query))
            {
                continue;
            }

            next.Add(new AuditRow(item));
        }

        var selectedUtc = SelectedAudit?.Source.Utc;
        var selectedKind = SelectedAudit?.Source.Kind;
        VisibleAudit.Clear();
        foreach (var row in next)
        {
            VisibleAudit.Add(row);
        }

        SelectedAudit = VisibleAudit.FirstOrDefault(row =>
            row.Source.Utc == selectedUtc && row.Source.Kind == selectedKind)
            ?? VisibleAudit.FirstOrDefault();
    }

    private void ReplaceVisibleItems(List<VaultListItem> next)
    {
        var current = VisibleItems;
        if (current.Count == next.Count)
        {
            var sameOrder = true;
            for (var i = 0; i < next.Count; i++)
            {
                if (current[i].Id != next[i].Id)
                {
                    sameOrder = false;
                    break;
                }
            }

            if (sameOrder)
            {
                for (var i = 0; i < next.Count; i++)
                {
                    if (!SameVisual(current[i], next[i]))
                    {
                        current[i] = next[i];
                    }
                }

                return;
            }
        }

        current.Clear();
        foreach (var item in next)
        {
            current.Add(item);
        }
    }

    private void ReplaceVisibleMedia(List<MediaGalleryRow> next)
    {
        VisibleMedia.Clear();
        foreach (var row in next)
        {
            VisibleMedia.Add(row);
        }
    }

    private async Task LoadGalleryThumbnailsAsync(IReadOnlyList<MediaGalleryRow> rows)
    {
        if (!ShowMediaPhotoGallery)
        {
            return;
        }

        var generation = ++_mediaThumbGeneration;
        for (var i = 0; i < rows.Count; i++)
        {
            if (generation != _mediaThumbGeneration || !IsMediaSection || !IsUnlocked)
            {
                return;
            }

            var row = rows[i];
            if (row.Category != MediaCategory.Photo || row.HasThumbnail)
            {
                continue;
            }

            var entry = _store.FindMedia(row.Id);
            if (entry is null || entry.ByteLength > MaximumGalleryPreviewBytes)
            {
                continue;
            }

            try
            {
                using var buffer = new MemoryStream();
                await _store.DecryptMediaAsync(entry.Id, buffer).ConfigureAwait(true);
                if (generation != _mediaThumbGeneration || !IsMediaSection)
                {
                    return;
                }

                var bytes = buffer.ToArray();
                try
                {
                    var image = new BitmapImage { DecodePixelWidth = 240 };
                    using var ras = new InMemoryRandomAccessStream();
                    await ras.WriteAsync(bytes.AsBuffer());
                    ras.Seek(0);
                    await image.SetSourceAsync(ras);
                    if (generation != _mediaThumbGeneration || !IsMediaSection)
                    {
                        return;
                    }

                    _mediaThumbs[row.Id] = image;
                    row.Thumbnail = image;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }
            catch (Exception)
            {
            }
        }
    }

    private void RebuildMediaSortChoices()
    {
        _rebuildingMediaSort = true;
        try
        {
            var selected = _mediaSortKey;
            MediaSortChoices.Clear();
            MediaSortChoices.Add(new FolderFilterChoice(MediaGalleryRules.SortDateNew, UiStrings.Get("MediaSortDateNew")));
            MediaSortChoices.Add(new FolderFilterChoice(MediaGalleryRules.SortDateOld, UiStrings.Get("MediaSortDateOld")));
            MediaSortChoices.Add(new FolderFilterChoice(MediaGalleryRules.SortSizeLarge, UiStrings.Get("MediaSortSizeLarge")));
            MediaSortChoices.Add(new FolderFilterChoice(MediaGalleryRules.SortSizeSmall, UiStrings.Get("MediaSortSizeSmall")));
            MediaSortChoices.Add(new FolderFilterChoice(MediaGalleryRules.SortName, UiStrings.Get("MediaSortName")));
            MediaSortChoices.Add(new FolderFilterChoice(MediaGalleryRules.SortTag, UiStrings.Get("MediaSortTag")));
            _mediaSortKey = MediaSortChoices.Any(choice => choice.Key == selected)
                ? selected
                : MediaGalleryRules.SortDateNew;
            OnPropertyChanged(nameof(SelectedMediaSort));
        }
        finally
        {
            _rebuildingMediaSort = false;
        }
    }

    private void ResetFolderFilter()
    {
        _selectedFolderFilter = null;
    }

    private string FolderForNewItem()
    {
        var key = _selectedFolderFilter?.Key;
        return string.IsNullOrEmpty(key) || key == VaultOrganizer.AllKey
            ? string.Empty
            : key;
    }

    private void RebuildFolderUi()
    {
        var names = VaultOrganizer.DistinctFolders(
            IsMediaSection
                ? _store.Media.Select(static entry => entry.Folder)
                : _store.Items.Select(static item => item.Folder));
        var selectedKey = _selectedFolderFilter?.Key ?? VaultOrganizer.AllKey;
        _rebuildingFolders = true;
        try
        {
            FolderSuggestions.Clear();
            foreach (var name in names)
            {
                FolderSuggestions.Add(name);
            }

            FolderFilters.Clear();
            FolderFilters.Add(new FolderFilterChoice(VaultOrganizer.AllKey, IsMediaSection ? UiStrings.Get("MediaTagAll") : UiStrings.Get("FolderAll")));
            FolderFilters.Add(new FolderFilterChoice(VaultOrganizer.UnfiledKey, IsMediaSection ? UiStrings.Get("MediaTagUnfiled") : UiStrings.Get("FolderUnfiled")));
            foreach (var name in names)
            {
                FolderFilters.Add(new FolderFilterChoice(name, name));
            }

            _selectedFolderFilter = FolderFilters.FirstOrDefault(choice =>
                    string.Equals(choice.Key, selectedKey, StringComparison.OrdinalIgnoreCase))
                ?? FolderFilters[0];
            OnPropertyChanged(nameof(SelectedFolderFilter));
        }
        finally
        {
            _rebuildingFolders = false;
        }
    }

    private static bool SameVisual(VaultListItem left, VaultListItem right)
    {
        return left.Title == right.Title
            && left.Username == right.Username
            && left.HostLabel == right.HostLabel
            && left.KindLabel == right.KindLabel
            && left.FolderLabel == right.FolderLabel
            && left.IdenticonSeed == right.IdenticonSeed;
    }

    private async void DebounceSearch()
    {
        _searchDebounceCancellation?.Cancel();
        _searchDebounceCancellation?.Dispose();
        _searchDebounceCancellation = new CancellationTokenSource();
        var token = _searchDebounceCancellation.Token;

        try
        {
            await Task.Delay(160, token);
            RefreshVisibleItems();
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void RefreshHealth()
    {
        _ = RefreshHealthAsync();
    }

    private void RefreshMasterRotation()
    {
        OnPropertyChanged(nameof(MasterRotationStatus));
        OnPropertyChanged(nameof(MasterRotationOverdue));
        OnPropertyChanged(nameof(MasterRotationSoon));
        ChangeMasterCommand.NotifyCanExecuteChanged();
    }

    private async Task RefreshHealthAsync()
    {
        var generation = ++_healthGeneration;
        if (!IsUnlocked)
        {
            HealthFindings.Clear();
            OnPropertyChanged(nameof(HealthSummary));
            return;
        }

        var snapshot = _store.Items.ToArray();
        var now = TrustedUtc;
        var findings = await Task.Run(() => VaultHealthService.Analyze(snapshot, now)).ConfigureAwait(true);
        if (generation != _healthGeneration || !IsUnlocked)
        {
            return;
        }

        var merged = findings.ToList();
        if (!IsDecoySession && _store.Settings.MasterChangedUtc is { } changed)
        {
            if (MasterPasswordPolicy.IsOverdue(changed, TrustedUtc))
            {
                merged.Insert(0, new HealthFinding
                {
                    ItemId = Guid.Empty,
                    Title = UiStrings.Get("ChangeMasterTitle"),
                    Severity = "High",
                    Detail = UiStrings.Get("HealthMasterOverdue")
                });
            }
            else if (MasterPasswordPolicy.IsWarning(changed, TrustedUtc))
            {
                merged.Insert(0, new HealthFinding
                {
                    ItemId = Guid.Empty,
                    Title = UiStrings.Get("ChangeMasterTitle"),
                    Severity = "Medium",
                    Detail = UiStrings.Format(
                        "HealthMasterSoon",
                        MasterPasswordPolicy.DaysRemaining(changed, TrustedUtc))
                });
            }
        }

        ReplaceHealthFindings(merged);
        OnPropertyChanged(nameof(HealthSummary));
    }

    private void ReplaceHealthFindings(IReadOnlyList<HealthFinding> findings)
    {
        if (HealthFindings.Count == findings.Count)
        {
            var same = true;
            for (var i = 0; i < findings.Count; i++)
            {
                if (HealthFindings[i].ItemId != findings[i].ItemId
                    || HealthFindings[i].Title != findings[i].Title
                    || HealthFindings[i].Detail != findings[i].Detail
                    || HealthFindings[i].Severity != findings[i].Severity)
                {
                    same = false;
                    break;
                }
            }

            if (same)
            {
                return;
            }
        }

        HealthFindings = new ObservableCollection<HealthFinding>(findings);
    }

    private static bool Matches(VaultItem item, string query)
    {
        return item.Title.Contains(query, StringComparison.OrdinalIgnoreCase)
            || item.Url.Contains(query, StringComparison.OrdinalIgnoreCase)
            || item.Username.Contains(query, StringComparison.OrdinalIgnoreCase)
            || item.AliasEmail.Contains(query, StringComparison.OrdinalIgnoreCase)
            || item.HostLabel.Contains(query, StringComparison.OrdinalIgnoreCase)
            || item.Mailbox.Contains(query, StringComparison.OrdinalIgnoreCase)
            || item.KindLabel.Contains(query, StringComparison.OrdinalIgnoreCase)
            || (item.Folder ?? string.Empty).Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private static bool Matches(MediaEntry item, string query)
    {
        return item.Title.Contains(query, StringComparison.OrdinalIgnoreCase)
            || item.OriginalName.Contains(query, StringComparison.OrdinalIgnoreCase)
            || item.Category.Contains(query, StringComparison.OrdinalIgnoreCase)
            || item.ContentType.Contains(query, StringComparison.OrdinalIgnoreCase)
            || (item.Folder ?? string.Empty).Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private async Task AddMediaAsync(string category)
    {
        if (!IsUnlocked || PickMediaRequested is null)
        {
            return;
        }

        OpenMediaGallery(category);
        var picked = await PickMediaRequested.Invoke(category);
        if (picked is null)
        {
            return;
        }

        var (name, stream, length) = picked.Value;
        try
        {
            if (length > MediaCryptography.MaximumFileBytes)
            {
                SetStatus("MediaTooLarge", name);
                return;
            }

            IsBusy = true;
            var entry = await _store.ImportMediaAsync(stream, name, category, length, FolderForNewItem());
            NoteAudit(AuditKind.MediaAdded, string.Empty, entry.Title, entry.Category, entry.Id);
            await _store.SaveAsync();
            RefreshVisibleItems();
            SelectedItem = VisibleItems.FirstOrDefault(item => item.Id == entry.Id);
            SetStatus("MediaSaved");
        }
        catch (Exception)
        {
            SetStatus("MediaCouldNotAdd");
        }
        finally
        {
            await stream.DisposeAsync();
            IsBusy = false;
        }
    }

    private async Task LoadMediaEditorAsync(MediaEntry entry)
    {
        _editingId = entry.Id;
        EditMediaTitle = entry.Title;
        EditFolder = entry.Folder;
        MediaOriginalName = entry.OriginalName;
        MediaSizeLabel = VaultListItem.From(entry).Username;
        MediaTypeLabel = VaultListItem.From(entry).KindLabel;
        NotifyMediaCommands();
        NotifyEditorCommands();
        RefreshUsageLabels();
        ClearMediaPreview();
        if (entry.Category != MediaCategory.Photo || entry.ByteLength > MaximumInMemoryPreviewBytes)
        {
            return;
        }

        try
        {
            using var buffer = new MemoryStream();
            await _store.DecryptMediaAsync(entry.Id, buffer);
            if (_editingId != entry.Id || !IsMediaSection)
            {
                return;
            }

            var bytes = buffer.ToArray();
            try
            {
                var image = new BitmapImage();
                using var ras = new InMemoryRandomAccessStream();
                await ras.WriteAsync(bytes.AsBuffer());
                ras.Seek(0);
                await image.SetSourceAsync(ras);
                if (_editingId != entry.Id || !IsMediaSection)
                {
                    return;
                }

                MediaPreview = image;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        catch (Exception)
        {
            SetStatus("MediaCouldNotOpen");
        }
    }

    private async Task SaveMediaTitleAsync()
    {
        if (!IsUnlocked || _editingId == Guid.Empty)
        {
            return;
        }

        _store.RenameMedia(_editingId, EditMediaTitle);
        _store.SetMediaFolder(_editingId, EditFolder);
        await _store.SaveAsync();
        RefreshVisibleItems();
        SetStatus("MediaSaved");
    }

    private async Task ExportMediaAsync()
    {
        if (!IsUnlocked || _editingId == Guid.Empty || SaveMediaRequested is null)
        {
            return;
        }

        var entry = _store.FindMedia(_editingId);
        if (entry is null)
        {
            return;
        }

        try
        {
            IsBusy = true;
            var id = entry.Id;
            var saved = await SaveMediaRequested.Invoke(entry.OriginalName, async destination =>
            {
                await _store.DecryptMediaAsync(id, destination);
            });
            if (saved)
            {
                NoteUsed(id, AuditMethod.Export);
                SetStatus("MediaExported");
            }
        }
        catch (Exception)
        {
            SetStatus("MediaCouldNotOpen");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task DeleteMediaItemAsync()
    {
        if (_editingId == Guid.Empty)
        {
            return;
        }

        if (ConfirmAsync is not null
            && !await ConfirmAsync(UiStrings.Get("MediaDeleteTitle"), UiStrings.Get("MediaDeleteBody"), UiStrings.Get("Delete")))
        {
            return;
        }

        var removing = _store.FindMedia(_editingId);
        NoteAudit(AuditKind.Deleted, string.Empty, removing?.Title, removing?.Category, _editingId);
        await _store.DeleteMediaAsync(_editingId);
        ClearMediaPreview();
        _editingId = Guid.Empty;
        RefreshVisibleItems();
        if (VisibleItems.Count > 0)
        {
            SelectedItem = VisibleItems[0];
        }
        else
        {
            EditMediaTitle = string.Empty;
            MediaOriginalName = string.Empty;
            MediaSizeLabel = string.Empty;
            MediaTypeLabel = string.Empty;
            SetStatus("MediaEmpty");
            NotifyMediaCommands();
            NotifyEditorCommands();
            return;
        }

        SetStatus("MediaDeleted");
    }

    private void ClearMediaPreview()
    {
        MediaPreview = null;
    }

    private void NotifyMediaCommands()
    {
        ShowLoginsCommand.NotifyCanExecuteChanged();
        ShowMediaCommand.NotifyCanExecuteChanged();
        AddMediaPhotoCommand.NotifyCanExecuteChanged();
        AddMediaVideoCommand.NotifyCanExecuteChanged();
        AddMediaAudioCommand.NotifyCanExecuteChanged();
        AddMediaFileCommand.NotifyCanExecuteChanged();
        AddCurrentMediaCommand.NotifyCanExecuteChanged();
        ExportMediaCommand.NotifyCanExecuteChanged();
        SaveMediaCommand.NotifyCanExecuteChanged();
    }

    private void GenerateTotp()
    {
        EditTotpSecret = TotpService.GenerateSecret();
        SetStatus("TotpCreated");
    }

    private void GenerateAlias()
    {
        EditKindIndex = 1;
        if (string.IsNullOrWhiteSpace(EditTitle))
        {
            EditTitle = string.IsNullOrWhiteSpace(EditUrl) ? "Alias" : EditUrl;
        }

        EditAliasEmail = AliasGenerator.Generate(ActiveMailboxEmail(), AliasDomain, string.IsNullOrWhiteSpace(EditUrl) ? EditTitle : EditUrl);
        if (SelectedMailboxProfile is not null)
        {
            EditMailbox = SelectedMailboxProfile.DisplayLabel;
        }
        EditUsername = EditAliasEmail;
        SetStatus("AliasCreated");
    }

    private void ComposeAlias()
    {
        Copy(EditAliasEmail);
        ComposeRequested?.Invoke(EditAliasEmail);
    }

    private async Task SaveSettingsAsync()
    {
        await PersistMailboxProfilesAsync(SelectedMailboxProfile?.Id, makeSelectedDefault: false);
        SetStatus("MailboxSaved");
    }

    private async Task PersistMailboxProfilesAsync(Guid? selectId, bool makeSelectedDefault)
    {
        MailboxProfileService.Migrate(_store.Settings);
        if (makeSelectedDefault && selectId is Guid defaultId)
        {
            foreach (var profile in _store.Settings.Profiles)
            {
                profile.IsDefault = profile.Id == defaultId;
            }
        }

        _store.Settings.AliasDomain = AliasDomain.Trim().TrimStart('@');
        _store.UpdateSettings(_store.Settings);
        await _store.SaveAsync();
        LoadSettings(selectId);
    }

    private void LoadSettings(Guid? selectId = null)
    {
        MailboxProfileService.Migrate(_store.Settings);
        PrimaryEmail = _store.Settings.PrimaryEmail;
        AliasDomain = _store.Settings.AliasDomain;
        MailboxesText = string.Join(", ", _store.Settings.Mailboxes);
        _loadingMailboxes = true;
        try
        {
            MailboxProfiles.Clear();
            foreach (var profile in _store.Settings.Profiles)
            {
                MailboxProfiles.Add(profile);
            }

            _selectedMailboxProfile = selectId is Guid id
                ? MailboxProfiles.FirstOrDefault(profile => profile.Id == id)
                : null;
            _selectedMailboxProfile ??= MailboxProfileService.Default(MailboxProfiles);
            OnPropertyChanged(nameof(SelectedMailboxProfile));
        }
        finally
        {
            _loadingMailboxes = false;
        }

        AddMailboxCommand.NotifyCanExecuteChanged();
        RemoveMailboxCommand.NotifyCanExecuteChanged();
        MakeDefaultMailboxCommand.NotifyCanExecuteChanged();
    }

    private void ClearMailboxState()
    {
        _loadingMailboxes = true;
        try
        {
            MailboxProfiles.Clear();
            _selectedMailboxProfile = null;
            OnPropertyChanged(nameof(SelectedMailboxProfile));
        }
        finally
        {
            _loadingMailboxes = false;
        }

        PrimaryEmail = string.Empty;
        AliasDomain = string.Empty;
        MailboxesText = string.Empty;
        NewMailboxEmail = string.Empty;
    }

    private async Task EnableHelloAsync()
    {
        var availability = await UserConsentVerifier.CheckAvailabilityAsync();
        if (availability != UserConsentVerifierAvailability.Available)
        {
            SetStatus("HelloUnavailable");
            return;
        }

        if (Occupants.Count > 1)
        {
            var accepted = ConfirmAsync is not null
                && await ConfirmAsync(UiStrings.Get("HelloSharedTitle"), SharedPcGuidance.HelloCannotTellPeopleApart + UiStrings.Get("HelloSharedConfirm"), null);
            if (!accepted)
            {
                return;
            }
        }

        var result = await UserConsentVerifier.RequestVerificationAsync(UiStrings.Get("ProtectHello"));
        if (result != UserConsentVerificationResult.Verified)
        {
            return;
        }

        await _store.EnableHelloAsync();
        HelloAvailable = true;
        SetStatus(Occupants.Count > 1 ? "HelloOnShared" : "HelloOnUser");
    }

    public byte[] ProtectRecoveryExportWithHello(RecoveryMaterials materials)
    {
        return _store.ProtectRecoveryWithHello(materials);
    }

    private async Task ShareCurrentAsync()
    {
        if (_editingId == Guid.Empty || SaveFileRequested is null)
        {
            return;
        }

        var password = await AskSharePasswordAsync!(UiStrings.Get("ShareThisItem"));
        if (password is null)
        {
            return;
        }

        var blob = await Task.Run(() => _store.ExportItems([_editingId], password));
        await SaveFileRequested.Invoke("stem-share.spgs", blob);
        SetStatus("ShareSaved");
    }

    private async Task ShareVaultAsync()
    {
        if (SaveFileRequested is null)
        {
            return;
        }

        var password = await AskSharePasswordAsync!(UiStrings.Get("ShareVaultCopyTitle"));
        if (password is null)
        {
            return;
        }

        var blob = await Task.Run(() => _store.ExportItems(_store.Items.Select(item => item.Id), password));
        await SaveFileRequested.Invoke("stem-vault-share.spgs", blob);
        SetStatus("ShareVaultSaved");
    }

    private async Task ExportEmergencyAsync()
    {
        if (SaveFileRequested is null)
        {
            return;
        }

        var password = await AskSharePasswordAsync!(UiStrings.Get("EmergencyTitle"));
        if (password is null)
        {
            return;
        }

        var blob = await Task.Run(() => _store.ExportAll(password));
        await SaveFileRequested.Invoke("stem-emergency.spgs", blob);
        SetStatus("EmergencySaved");
    }

    private async Task ExportPortableAsync()
    {
        if (!CanExportPortable() || SaveFileRequested is null || ConfirmAsync is null || AskLabeledPasswordAsync is null)
        {
            return;
        }

        var accepted = await ConfirmAsync(
            UiStrings.Get("PortableExportConfirmTitle"),
            UiStrings.Get("PortableExportConfirmBody"),
            UiStrings.Get("PortableExportConfirm"));
        if (!accepted)
        {
            return;
        }

        var typed = await AskLabeledPasswordAsync(
            UiStrings.Get("PortableExportPasswordTitle"),
            UiStrings.Get("PortableExportPasswordHeader"),
            UiStrings.Get("PortableExportPasswordHint"));
        if (typed is null)
        {
            return;
        }

        if (!_store.VerifyMasterPassword(typed))
        {
            SetStatus("ShamirWrongPassword");
            return;
        }

        byte[]? data = null;
        IsBusy = true;
        try
        {
            data = await Task.Run(() => _store.ExportPortable()).ConfigureAwait(true);
            var hadMedia = _store.Media.Count > 0;
            await SaveFileRequested.Invoke("stem-portable.spgp", data);
            SetStatus(hadMedia ? "PortableSavedNoMedia" : "PortableSaved");
        }
        catch (Exception)
        {
            SetStatus("PortableCouldNotExport");
        }
        finally
        {
            if (data is not null)
            {
                CryptographicOperations.ZeroMemory(data);
            }

            IsBusy = false;
        }
    }

    private bool CanExportPortable() => IsUnlocked && !IsBusy && !IsDecoySession;

    private async Task OpenPortableAsync()
    {
        if (!CanOpenPortable() || PickFileRequested is null)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(MasterPassword))
        {
            SetStatus("PortableNeedMaster");
            return;
        }

        if (SelectedOccupant is null)
        {
            if (!OccupantRules.CanAddOccupant(Occupants.Count))
            {
                SetStatus("ChoosePerson");
                return;
            }

            var created = await _occupants.AddAsync(string.IsNullOrWhiteSpace(NewPersonName) ? UiStrings.Get("MyVault") : NewPersonName);
            RefreshOccupantList();
            SelectOccupantQuietly(created);
        }

        if (SelectedOccupant is null)
        {
            SetStatus("ChoosePerson");
            return;
        }

        _store.SelectFolder(SelectedOccupant.FolderName);
        if (await _store.ExistsWithoutCreatingAsync())
        {
            SetStatus("PortableTargetHasVault");
            return;
        }

        var picked = await PickFileRequested.Invoke();
        if (picked is null)
        {
            return;
        }

        var master = MasterPassword;
        byte[]? data = picked.Value.Data;
        IsBusy = true;
        try
        {
            var bind = await _store.InstallPortableAsync(data, master).ConfigureAwait(true);
            NeedsSetup = false;
            IsLocked = true;
            _failedUnlocks = 0;
            var person = CurrentPersonLabel;
            ClearMasterFields();
            _afterHuman = async () =>
            {
                if (SelectedOccupant is not null)
                {
                    await _occupants.TouchAsync(SelectedOccupant.Id);
                }

                await AfterUnlockAsync().ConfigureAwait(true);
                SetStatus("PortableOpened", person);
            };
            BeginHumanVerification(bind);
            SetStatus("HumanVerificationHint");
        }
        catch (InvalidOperationException exception) when (exception.Message is "PortableTargetHasVault" or "PortableIsDpapi" or "PortableUnrecognized")
        {
            SetStatus(exception.Message);
        }
        catch (ArgumentException exception)
        {
            SetStatusRaw(exception.Message);
        }
        catch (CryptographicException)
        {
            SetStatus("PortableWrongMaster");
        }
        catch (Exception)
        {
            SetStatus("PortableCouldNotOpen");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
            IsBusy = false;
        }
    }

    private bool CanOpenPortable() => NeedsSetup && !IsBusy;

    private bool CanCreateShamir() => IsUnlocked && !IsBusy && !IsDecoySession;

    private bool CanRecoverShamir() => ShowUnlock && !IsBusy;

    private bool CanForgotMaster() => ShowUnlock && !IsBusy && RecoveryConfigured;

    private bool CanChangeMaster() => IsUnlocked && !IsBusy && !IsDecoySession && !_changingMaster && ConfirmAsync is not null && AskLabeledPasswordAsync is not null && AskNewMasterAsync is not null;

    private async Task ChangeMasterAsync(bool required)
    {
        if ((!CanChangeMaster() && !required) || ConfirmAsync is null || AskLabeledPasswordAsync is null || AskNewMasterAsync is null)
        {
            return;
        }

        if (IsDecoySession || !IsUnlocked)
        {
            return;
        }

        _changingMaster = true;
        ChangeMasterCommand.NotifyCanExecuteChanged();
        try
        {
            var accepted = await ConfirmAsync(
                UiStrings.Get(required ? "MasterRotationDueTitle" : "ChangeMasterConfirmTitle"),
                UiStrings.Get(required ? "MasterRotationDueBody" : "ChangeMasterConfirmBody"),
                UiStrings.Get(required ? "ChangeMasterConfirm" : "ChangeMasterConfirm"));
            if (!accepted)
            {
                if (required)
                {
                    Lock("MasterRotationLocked");
                }

                return;
            }

            var current = await AskLabeledPasswordAsync(
                UiStrings.Get("ChangeMasterCurrentTitle"),
                UiStrings.Get("ChangeMasterCurrentHeader"),
                UiStrings.Get("ChangeMasterCurrentHint"));
            if (current is null)
            {
                if (required)
                {
                    Lock("MasterRotationLocked");
                }

                return;
            }

            if (!_store.VerifyMasterPassword(current))
            {
                SetStatus("MasterWrongCurrent");
                if (required)
                {
                    Lock("MasterRotationLocked");
                }

                return;
            }

            var next = await AskNewMasterAsync().ConfigureAwait(true);
            if (next is null)
            {
                if (required)
                {
                    Lock("MasterRotationLocked");
                }

                return;
            }

            if (!VaultCryptography.FixedEquals(next.Value.Password, next.Value.Confirm))
            {
                SetStatus("PasswordsDoNotMatch");
                if (required)
                {
                    Lock("MasterRotationLocked");
                }

                return;
            }

            if (VaultCryptography.FixedEquals(current, next.Value.Password))
            {
                SetStatus("MasterSamePassword");
                if (required)
                {
                    Lock("MasterRotationLocked");
                }

                return;
            }

            IsBusy = true;
            try
            {
                await _store.ChangeMasterPasswordAsync(next.Value.Password, clearHello: true).ConfigureAwait(true);
            }
            catch (ArgumentException exception)
            {
                SetStatusRaw(exception.Message);
                if (required)
                {
                    Lock("MasterRotationLocked");
                }

                return;
            }
            finally
            {
                IsBusy = false;
            }

            HelloAvailable = await _store.HelloEnabledAsync().ConfigureAwait(true);
            UsbUnlockAvailable = await _store.UsbUnlockEnabledAsync().ConfigureAwait(true);
            RefreshMasterRotation();
            _ = RefreshHealthAsync();
            SetStatus("MasterChanged");
        }
        finally
        {
            _changingMaster = false;
            ChangeMasterCommand.NotifyCanExecuteChanged();
        }
    }

    private bool CanSetupRecovery() => IsUnlocked && !IsBusy && !IsDecoySession;

    private async Task OfferMissingRecoveryKitAsync()
    {
        if (IsDecoySession || RecoveryConfigured || _recoveryPrompted || ShowRecoveryKitAsync is null)
        {
            return;
        }

        await IssueRecoveryPhraseOnceAsync(null).ConfigureAwait(true);
        if (RecoveryConfigured)
        {
            await TryEnableHelloForRecoveryAsync().ConfigureAwait(true);
        }
    }

    private async Task IssueRecoveryPhraseOnceAsync(string? masterPasswordToAvoid)
    {
        _recoveryPrompted = true;
        if (ShowRecoveryKitAsync is null)
        {
            return;
        }

        var kit = VaultRecovery.Create(masterPasswordToAvoid);
        IsBusy = false;
        var accepted = await ShowRecoveryKitAsync(kit).ConfigureAwait(true);
        if (!accepted)
        {
            SetStatus("RecoveryLater");
            return;
        }

        IsBusy = true;
        await _store.SaveRecoveryVerifierAsync(kit).ConfigureAwait(true);
        RecoveryConfigured = true;
    }

    private async Task TryEnableHelloForRecoveryAsync()
    {
        if (!RecoveryConfigured)
        {
            return;
        }

        var availability = await UserConsentVerifier.CheckAvailabilityAsync();
        if (availability != UserConsentVerifierAvailability.Available || ConfirmAsync is null)
        {
            SetStatus("RecoveryCreated");
            return;
        }

        var accepted = await ConfirmAsync(
            UiStrings.Get("EnableHello"),
            UiStrings.Get("RecoveryCreated") + " " + SharedPcGuidance.HelloCannotTellPeopleApart,
            UiStrings.Get("EnableHello"));
        if (!accepted)
        {
            SetStatus("RecoveryCreated");
            return;
        }

        await EnableHelloAsync().ConfigureAwait(true);
    }

    private async Task SetupRecoveryAsync()
    {
        if (!CanSetupRecovery() || ShowRecoveryKitAsync is null)
        {
            return;
        }

        if (RecoveryConfigured)
        {
            if (ConfirmAsync is null)
            {
                return;
            }

            var replace = await ConfirmAsync(
                UiStrings.Get("RecoveryReplaceTitle"),
                UiStrings.Get("RecoveryReplaceBody"),
                UiStrings.Get("RecoveryReplace"));
            if (!replace)
            {
                return;
            }
        }

        IsBusy = true;
        try
        {
            await IssueRecoveryPhraseOnceAsync(null).ConfigureAwait(true);
            if (RecoveryConfigured)
            {
                SetStatus("RecoveryCreated");
            }
        }
        catch (Exception)
        {
            SetStatus("RecoveryCouldNotReset");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ForgotMasterAsync()
    {
        if (!CanForgotMaster())
        {
            return;
        }

        if (!HelloAvailable)
        {
            SetStatus("RecoveryNeedsHello");
            return;
        }

        if (AskRecoverySecretAsync is null || AskNewMasterAsync is null)
        {
            return;
        }

        var availability = await UserConsentVerifier.CheckAvailabilityAsync();
        if (availability != UserConsentVerifierAvailability.Available)
        {
            SetStatus("HelloUnavailablePc");
            return;
        }

        var hello = await UserConsentVerifier.RequestVerificationAsync(UiStrings.Get("RecoveryHelloFirst"));
        if (hello != UserConsentVerificationResult.Verified)
        {
            SetStatus("HelloCancelled");
            return;
        }

        var secret = await AskRecoverySecretAsync().ConfigureAwait(true);
        if (string.IsNullOrWhiteSpace(secret))
        {
            return;
        }

        IsBusy = true;
        try
        {
            var key = await _store.LoadHelloKeyAsync().ConfigureAwait(true);
            var bundle = await _store.LoadRecoveryVerifierBundleAsync().ConfigureAwait(true);
            try
            {
                if (!_store.RecoveryBindingIsValid(bundle.PlainBlob, key))
                {
                    key.Dispose();
                    SetStatus("RecoveryTampered");
                    return;
                }

                var ok = await Task.Run(() =>
                    VaultRecovery.LooksLikeKey(secret)
                        ? VaultRecovery.VerifyKey(secret, bundle.Verifier)
                        : VaultRecovery.VerifyPhrase(secret, bundle.Verifier)).ConfigureAwait(true);
            if (!ok)
            {
                key.Dispose();
                _failedUnlocks++;
                var delaySeconds = Math.Min(32, 1 << Math.Min(_failedUnlocks, 5));
                _nextUnlockAllowed = DateTimeOffset.UtcNow.AddSeconds(delaySeconds);
                await RecordLockedFailAsync(AuditMethod.Recovery);
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(delaySeconds, 4)));
                SetStatus("RecoveryWrong");
                return;
            }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bundle.PlainBlob);
            }

            var bind = await _store.AuthenticateWithKeyAsync(key).ConfigureAwait(true);
            _unlockMethod = AuditMethod.Recovery;
            _afterHuman = async () =>
            {
                var next = await AskNewMasterAsync().ConfigureAwait(true);
                if (next is null)
                {
                    Lock();
                    return;
                }

                if (!VaultCryptography.FixedEquals(next.Value.Password, next.Value.Confirm))
                {
                    Lock();
                    SetStatus("PasswordsDoNotMatch");
                    return;
                }

                await _store.ChangeMasterPasswordAsync(next.Value.Password).ConfigureAwait(true);
                await AfterUnlockAsync().ConfigureAwait(true);
                SetStatus("RecoveryMasterChanged");
            };
            BeginHumanVerification(bind);
            SetStatus("HumanVerificationHint");
            return;
        }
        catch (ArgumentException exception)
        {
            if (_store.IsUnlocked)
            {
                Lock();
            }

            SetStatusRaw(exception.Message);
        }
        catch (Exception)
        {
            if (_store.IsUnlocked)
            {
                Lock();
            }

            SetStatus("RecoveryCouldNotReset");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task CreateShamirCardsAsync()
    {
        if (!CanCreateShamir() || ConfirmAsync is null || AskLabeledPasswordAsync is null || SaveShamirCardsAsync is null)
        {
            return;
        }

        var accepted = await ConfirmAsync(
            UiStrings.Get("ShamirConfirmTitle"),
            UiStrings.Get("ShamirConfirmBody"),
            UiStrings.Get("ShamirConfirm"));
        if (!accepted)
        {
            return;
        }

        var password = await AskLabeledPasswordAsync(
            UiStrings.Get("ShamirAskTitle"),
            UiStrings.Get("ShamirAskHeader"),
            UiStrings.Get("ShamirAskHint"));
        if (password is null)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var matches = await Task.Run(() => _store.VerifyMasterPassword(password)).ConfigureAwait(true);
            if (!matches)
            {
                SetStatus("ShamirWrongPassword");
                return;
            }

            IReadOnlyList<ShamirCard> cards;
            try
            {
                cards = ShamirSecretSharing.SplitPassword(
                    password,
                    SelectedOccupant?.DisplayName ?? "Stem",
                    DateTimeOffset.UtcNow);
            }
            catch (ArgumentException)
            {
                SetStatus("ShamirTooLong");
                return;
            }

            var saved = await SaveShamirCardsAsync(cards).ConfigureAwait(true);
            if (saved)
            {
                SetStatus("ShamirSaved");
            }
        }
        catch (Exception)
        {
            SetStatus("ShamirCouldNotSave");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RecoverShamirAsync()
    {
        if (!CanRecoverShamir() || PickTextFilesAsync is null)
        {
            return;
        }

        var files = await PickTextFilesAsync().ConfigureAwait(true);
        if (files is null || files.Count == 0)
        {
            return;
        }

        string password;
        try
        {
            password = ShamirSecretSharing.CombinePassword(files);
        }
        catch (CryptographicException exception) when (exception.Message.Contains("Need any 2", StringComparison.Ordinal))
        {
            SetStatus("ShamirNeedTwo");
            return;
        }
        catch (CryptographicException)
        {
            SetStatus("ShamirUnrecognized");
            return;
        }
        catch (Exception)
        {
            SetStatus("ShamirUnrecognized");
            return;
        }

        MasterPassword = password;
        _afterHuman = async () =>
        {
            await AfterUnlockAsync().ConfigureAwait(true);
            SetStatus("ShamirRecovered");
        };
        await UnlockAsync().ConfigureAwait(true);
    }

    public void RefreshUsbDrives()
    {
        var selected = SelectedUsbDrive?.Letter;
        UsbDrives.Clear();
        foreach (var drive in UsbDriveService.ListRemovable())
        {
            UsbDrives.Add(drive);
        }

        SelectedUsbDrive = UsbDrives.FirstOrDefault(drive => drive.Letter == selected) ?? UsbDrives.FirstOrDefault();
        NotifyUsbCommands();
        if (UsbDrives.Count == 0)
        {
            SetStatus("UsbNoneFound");
        }
    }

    private bool CanPrepareUsbKey() => IsUnlocked && !IsBusy && !IsDecoySession && SelectedUsbDrive is not null;

    private bool CanRestoreUsbStorage() => !IsBusy && SelectedUsbDrive is not null;

    private bool CanRemoveUsbUnlock() => IsUnlocked && !IsBusy && !IsDecoySession && UsbUnlockAvailable;

    private bool CanUnlockWithUsb() => ShowUnlock && !IsBusy && UsbUnlockAvailable;

    private void NotifyUsbCommands()
    {
        RefreshUsbDrivesCommand.NotifyCanExecuteChanged();
        PrepareUsbKeyCommand.NotifyCanExecuteChanged();
        RestoreUsbStorageCommand.NotifyCanExecuteChanged();
        RemoveUsbUnlockCommand.NotifyCanExecuteChanged();
        UnlockWithUsbCommand.NotifyCanExecuteChanged();
    }

    private UsbFormatRequest CreateUsbFormatRequest()
    {
        var letter = SelectedUsbDrive?.Letter ?? string.Empty;
        var cluster = UsbDriveRules.ClusterBytes[UsbClusterIndex];
        return new UsbFormatRequest
        {
            Letter = letter,
            FileSystem = UsbDriveRules.FileSystems[UsbFileSystemIndex],
            Label = UsbVolumeLabel,
            QuickFormat = UsbQuickFormat,
            ClusterBytes = cluster == 0 ? null : cluster
        };
    }

    private async Task PrepareUsbKeyAsync()
    {
        if (!CanPrepareUsbKey() || ConfirmAsync is null || AskLabeledPasswordAsync is null || SelectedUsbDrive is null)
        {
            return;
        }

        var drive = SelectedUsbDrive;
        if (UsbFormatFirst)
        {
            var accepted = await ConfirmAsync(
                UiStrings.Get("UsbFormatTitle"),
                UiStrings.Format("UsbPrepareBody", drive.Letter, drive.DisplayLabel),
                UiStrings.Get("UsbFormatConfirm"));
            if (!accepted)
            {
                return;
            }
        }
        else
        {
            var accepted = await ConfirmAsync(
                UiStrings.Get("UsbPrepareTitle"),
                UiStrings.Get("UsbPrepareNoFormatBody"),
                UiStrings.Get("UsbPrepareConfirm"));
            if (!accepted)
            {
                return;
            }
        }

        var pin = await AskLabeledPasswordAsync(
            UiStrings.Get("UsbPinTitle"),
            UiStrings.Get("UsbPinHeader"),
            UiStrings.Get("UsbPinHint"));
        if (pin is null)
        {
            return;
        }

        IsBusy = true;
        var secret = UsbKeyCryptography.CreateSecret();
        try
        {
            if (UsbFormatFirst)
            {
                await UsbDriveService.FormatAsync(CreateUsbFormatRequest()).ConfigureAwait(true);
            }

            var blob = await Task.Run(() => UsbKeyCryptography.CreateStickBlob(secret, pin)).ConfigureAwait(true);
            await UsbDriveService.WriteStemKeyAsync(drive.Letter, blob, writeReadme: true).ConfigureAwait(true);
            await _store.EnableUsbUnlockAsync(secret).ConfigureAwait(true);
            UsbUnlockAvailable = true;
            RefreshUsbDrives();
            SetStatus("UsbKeyReady");
        }
        catch (ArgumentException)
        {
            SetStatus("UsbPinWeak");
        }
        catch (Exception)
        {
            SetStatus("UsbPrepareFailed");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            IsBusy = false;
        }
    }

    private async Task RestoreUsbStorageAsync()
    {
        if (!CanRestoreUsbStorage() || ConfirmAsync is null || SelectedUsbDrive is null)
        {
            return;
        }

        var drive = SelectedUsbDrive;
        var accepted = await ConfirmAsync(
            UiStrings.Get("UsbRestoreTitle"),
            UiStrings.Format("UsbRestoreBody", drive.Letter, drive.DisplayLabel),
            UiStrings.Get("UsbFormatConfirm"));
        if (!accepted)
        {
            return;
        }

        IsBusy = true;
        try
        {
            await UsbDriveService.FormatAsync(CreateUsbFormatRequest()).ConfigureAwait(true);
            if (IsUnlocked && !IsDecoySession)
            {
                await _store.DisableUsbUnlockAsync().ConfigureAwait(true);
                UsbUnlockAvailable = false;
            }

            RefreshUsbDrives();
            SetStatus("UsbRestored");
        }
        catch (Exception)
        {
            SetStatus("UsbFormatFailed");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RemoveUsbUnlockAsync()
    {
        if (!CanRemoveUsbUnlock() || ConfirmAsync is null)
        {
            return;
        }

        var accepted = await ConfirmAsync(
            UiStrings.Get("UsbRemoveTitle"),
            UiStrings.Get("UsbRemoveBody"),
            UiStrings.Get("UsbRemoveConfirm"));
        if (!accepted)
        {
            return;
        }

        await _store.DisableUsbUnlockAsync().ConfigureAwait(true);
        UsbUnlockAvailable = false;
        SetStatus("UsbRemoved");
    }

    private async Task UnlockWithUsbAsync()
    {
        if (!CanUnlockWithUsb() || AskLabeledPasswordAsync is null)
        {
            return;
        }

        if (DateTimeOffset.UtcNow < _nextUnlockAllowed)
        {
            SetStatus("TooManyAttempts");
            return;
        }

        var pin = await AskLabeledPasswordAsync(
            UiStrings.Get("UsbPinTitle"),
            UiStrings.Get("UsbPinHeader"),
            UiStrings.Get("UsbUnlockHint"));
        if (pin is null)
        {
            return;
        }

        var files = UsbDriveService.FindKeyFiles();
        if (files.Count == 0)
        {
            SetStatus("UsbNotInserted");
            return;
        }

        IsBusy = true;
        try
        {
            CryptographicException? last = null;
            foreach (var path in files)
            {
                byte[] blob;
                try
                {
                    blob = await UsbDriveService.ReadStemKeyAsync(path).ConfigureAwait(true);
                }
                catch (CryptographicException exception)
                {
                    last = exception;
                    continue;
                }

                byte[] secret;
                try
                {
                    secret = await Task.Run(() => UsbKeyCryptography.OpenStickBlob(blob, pin)).ConfigureAwait(true);
                }
                catch (CryptographicException exception)
                {
                    CryptographicOperations.ZeroMemory(blob);
                    last = exception;
                    continue;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(blob);
                }

                try
                {
                    var key = await _store.LoadUsbUnlockAsync(secret).ConfigureAwait(true);
                    var bind = await _store.AuthenticateWithKeyAsync(key).ConfigureAwait(true);
                    _unlockMethod = AuditMethod.Usb;
                    _afterHuman = async () =>
                    {
                        await AfterUnlockAsync().ConfigureAwait(true);
                        SetStatus("UsbUnlocked");
                    };
                    await ContinueAfterBindAsync(bind, allowHourSkip: true).ConfigureAwait(true);
                    return;
                }
                catch (CryptographicException exception)
                {
                    last = exception;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(secret);
                }
            }

            _failedUnlocks++;
            var delaySeconds = Math.Min(32, 1 << Math.Min(_failedUnlocks, 5));
            _nextUnlockAllowed = DateTimeOffset.UtcNow.AddSeconds(delaySeconds);
            await RecordLockedFailAsync(AuditMethod.Usb);
            SetStatus(last?.Message.Contains("PIN", StringComparison.OrdinalIgnoreCase) == true ? "UsbWrongPin" : "UsbUnlockFailed");
        }
        catch (Exception)
        {
            await RecordLockedFailAsync(AuditMethod.Usb);
            SetStatus("UsbUnlockFailed");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ImportShareAsync()
    {
        if (PickFileRequested is null)
        {
            return;
        }

        var picked = await PickFileRequested.Invoke();
        if (picked is null)
        {
            return;
        }

        var password = await AskSharePasswordAsync!(UiStrings.Get("ImportShareTitle"));
        if (password is null)
        {
            return;
        }

        var added = _store.ImportShare(picked.Value.Data, password);
        NoteAudit(AuditKind.Imported, string.Empty, added.ToString());
        await _store.SaveAsync();
        RefreshVisibleItems();
        RefreshHealth();
        SetStatus("ImportedItems", added);
    }

    private async Task ImportCsvAsync()
    {
        if (!CanImportCsv() || PickFileRequested is null || ConfirmAsync is null)
        {
            return;
        }

        var picked = await PickFileRequested.Invoke();
        if (picked is null)
        {
            return;
        }

        var data = picked.Value.Data;
        var isKeePass = KeePassKdbxImporter.LooksLike(data);
        string? keepassPassword = null;
        try
        {
            if (isKeePass)
            {
                if (AskLabeledPasswordAsync is null)
                {
                    return;
                }

                var acceptedKeePass = await ConfirmAsync(
                    UiStrings.Get("KeePassImportConfirmTitle"),
                    UiStrings.Get("KeePassImportConfirmBody"),
                    UiStrings.Get("KeePassImportConfirm"));
                if (!acceptedKeePass)
                {
                    return;
                }

                keepassPassword = await AskLabeledPasswordAsync(
                    UiStrings.Get("KeePassPasswordTitle"),
                    UiStrings.Get("KeePassPasswordHeader"),
                    UiStrings.Get("KeePassPasswordHint"));
                if (keepassPassword is null)
                {
                    return;
                }
            }
            else
            {
                var acceptedCsv = await ConfirmAsync(
                    UiStrings.Get("CsvImportConfirmTitle"),
                    UiStrings.Get("CsvImportConfirmBody") + Environment.NewLine + Environment.NewLine + UiStrings.Get("CsvImportWarning"),
                    UiStrings.Get("CsvImportConfirm"));
                if (!acceptedCsv)
                {
                    return;
                }
            }

            IsBusy = true;
            var result = isKeePass
                ? await Task.Run(() => KeePassKdbxImporter.Open(data, keepassPassword)).ConfigureAwait(true)
                : CsvVaultImporter.Parse(data);
            if (!result.Success)
            {
                SetStatus(result.ErrorKey!, result.ErrorArgs);
                return;
            }

            var added = 0;
            var skipped = 0;
            var incoming = result.Items;
            for (var i = incoming.Count - 1; i >= 0; i--)
            {
                var item = incoming[i];
                if (CsvVaultImporter.IsDuplicate(item, _store.Items))
                {
                    skipped++;
                    continue;
                }

                item.Id = Guid.NewGuid();
                _store.Add(item);
                added++;
            }

            if (added > 0)
            {
                NoteAudit(AuditKind.Imported, string.Empty, added.ToString());
                await _store.SaveAsync();
            }

            RefreshVisibleItems();
            RefreshHealth();
            if (isKeePass)
            {
                if (added == 0)
                {
                    SetStatus("KeePassImportedNone");
                }
                else if (skipped > 0)
                {
                    SetStatus("KeePassImportedWithSkip", added, skipped);
                }
                else
                {
                    SetStatus("KeePassImported", added);
                }
            }
            else if (added == 0)
            {
                SetStatus("CsvImportedNone");
            }
            else if (skipped > 0)
            {
                SetStatus("CsvImportedWithSkip", added, skipped);
            }
            else
            {
                SetStatus("CsvImported", added);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
            IsBusy = false;
        }
    }

    private bool CanImportCsv() => IsUnlocked && !IsBusy && !IsDecoySession;

    private async Task ExportCsvAsync()
    {
        if (!CanExportCsv() || SaveFileRequested is null || ConfirmAsync is null)
        {
            return;
        }

        var accepted = await ConfirmAsync(
            UiStrings.Get("CsvExportConfirmTitle"),
            UiStrings.Get("CsvExportConfirmBody") + Environment.NewLine + Environment.NewLine + UiStrings.Get("CsvImportWarning"),
            UiStrings.Get("CsvExportConfirm"));
        if (!accepted)
        {
            return;
        }

        byte[]? data = null;
        IsBusy = true;
        try
        {
            var result = CsvVaultExporter.Write(_store.Items);
            if (!result.Success)
            {
                SetStatus(result.ErrorKey!, result.ErrorArgs);
                return;
            }

            data = result.Data;
            await SaveFileRequested.Invoke("stem-passwords.csv", data);
            if (result.Skipped > 0)
            {
                SetStatus("CsvExportedWithSkip", result.Written, result.Skipped);
            }
            else
            {
                SetStatus("CsvExported", result.Written);
            }
        }
        finally
        {
            if (data is not null)
            {
                CryptographicOperations.ZeroMemory(data);
            }

            IsBusy = false;
        }
    }

    private bool CanExportCsv() => IsUnlocked && !IsBusy && !IsDecoySession && _store.Items.Count > 0;

    private async Task AddAttachmentAsync()
    {
        if (PickFileRequested is null || _editingId == Guid.Empty)
        {
            SetStatus("SaveItemFirst");
            return;
        }

        var picked = await PickFileRequested.Invoke();
        if (picked is null)
        {
            return;
        }

        var item = _store.Find(_editingId);
        if (item is null)
        {
            return;
        }

        _store.AddAttachment(item, picked.Value.Name, picked.Value.Data);
        await _store.SaveAsync();
        LoadEditor(item);
        SetStatus("FileAttached");
    }

    private void Copy(string text)
    {
        if (_clipboard.TryCopy(text))
        {
            NoteUsed();
            if (_clipboard.AutoClear)
            {
                SetStatus("CopiedClearsVault", ClipboardService.DefaultClearSeconds);
            }
            else
            {
                SetStatus("CopiedNoCloud");
            }
        }
    }

    private async Task RefreshTrustedTimeAsync()
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            _remoteSamples = await TrustedTimeClient.ProbeAsync(timeout.Token).ConfigureAwait(true);
            _clockConfirmed = TrustedClock.Agreeing(_remoteSamples).Count > 0;
        }
        catch (Exception)
        {
            _remoteSamples = [];
            _clockConfirmed = false;
        }

        OnPropertyChanged(nameof(ClockStatus));
        if (!IsUnlocked)
        {
            return;
        }

        var now = TrustedUtc;
        var floor = _store.Settings.ClockFloorUtc;
        if (floor is null || now > floor.Value.AddSeconds(1))
        {
            _store.Settings.ClockFloorUtc = now;
            try
            {
                await _store.SaveAsync().ConfigureAwait(true);
            }
            catch (Exception)
            {
            }
        }
    }

    private void NoteUsed(Guid? id = null, string? method = null)
    {
        if (!IsUnlocked)
        {
            return;
        }

        var target = id ?? (_editingId == Guid.Empty ? null : _editingId);
        if (target is not { } itemId)
        {
            return;
        }

        if (!_store.Touch(itemId, TrustedUtc, method ?? AuditMethod.Copy))
        {
            return;
        }

        RefreshUsageLabels();
        _ = PersistTouchAsync();
    }

    private async Task PersistTouchAsync()
    {
        try
        {
            await _store.SaveAsync().ConfigureAwait(true);
        }
        catch (Exception)
        {
        }
    }

    private void RefreshUsageLabels()
    {
        UsageLine = string.Empty;
        PasswordAgeWarning = string.Empty;
        if (!IsUnlocked)
        {
            OnPropertyChanged(nameof(UsageLine));
            OnPropertyChanged(nameof(PasswordAgeWarning));
            OnPropertyChanged(nameof(HasPasswordAgeWarning));
            return;
        }

        if (IsMediaSection)
        {
            var media = _editingId == Guid.Empty ? null : _store.FindMedia(_editingId);
            if (media is not null)
            {
                UsageLine = UiStrings.Format("ItemCreated", ItemUsage.FormatLocalDateTime(media.CreatedUtc));
                UsageLine += " · " + (media.LastUsedUtc is { } used
                    ? UiStrings.Format("ItemLastUsed", ItemUsage.FormatLocalDateTime(used))
                    : UiStrings.Get("ItemNeverUsed"));
            }
        }
        else if (_editingId != Guid.Empty)
        {
            var item = _store.Find(_editingId);
            if (item is not null)
            {
                UsageLine = UiStrings.Format("ItemCreated", ItemUsage.FormatLocalDateTime(item.CreatedUtc));
                UsageLine += " · " + (item.LastUsedUtc is { } used
                    ? UiStrings.Format("ItemLastUsed", ItemUsage.FormatLocalDateTime(used))
                    : UiStrings.Get("ItemNeverUsed"));
                if (ItemUsage.TracksPasswordAge(item.Kind) && !string.IsNullOrEmpty(item.Password))
                {
                    var changed = ItemUsage.PasswordChangedUtc(item);
                    UsageLine += " · " + UiStrings.Format("ItemPasswordChanged", ItemUsage.FormatLocalDate(changed));
                    var now = TrustedUtc;
                    if (MasterPasswordPolicy.IsOverdue(changed, now))
                    {
                        PasswordAgeWarning = UiStrings.Format("HealthPasswordOverdue", ItemUsage.FormatLocalDate(changed));
                    }
                    else if (MasterPasswordPolicy.IsWarning(changed, now))
                    {
                        PasswordAgeWarning = UiStrings.Format(
                            "HealthPasswordSoon",
                            ItemUsage.FormatLocalDate(MasterPasswordPolicy.DueUtc(changed)));
                    }
                }
            }
        }

        OnPropertyChanged(nameof(UsageLine));
        OnPropertyChanged(nameof(PasswordAgeWarning));
        OnPropertyChanged(nameof(HasPasswordAgeWarning));
    }

    private async void DebounceWifiQr()
    {
        _wifiQrDebounceCancellation?.Cancel();
        _wifiQrDebounceCancellation?.Dispose();
        _wifiQrDebounceCancellation = new CancellationTokenSource();
        var token = _wifiQrDebounceCancellation.Token;

        try
        {
            await Task.Delay(180, token);
            _ = RefreshWifiQrAsync();
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task RefreshWifiQrAsync()
    {
        var generation = ++_wifiQrGeneration;
        if (!ShowWifiFields || string.IsNullOrWhiteSpace(EditTitle))
        {
            WifiQrImage = null;
            return;
        }

        byte[] png;
        try
        {
            var payload = WifiQr.Payload(EditTitle.Trim(), EditPassword, WifiSecurityValue);
            png = await Task.Run(() => QrPng.Render(payload)).ConfigureAwait(true);
        }
        catch (Exception)
        {
            if (generation == _wifiQrGeneration)
            {
                WifiQrImage = null;
            }

            return;
        }

        if (generation != _wifiQrGeneration)
        {
            return;
        }

        var image = new BitmapImage();
        using var stream = new InMemoryRandomAccessStream();
        using (var writer = new DataWriter(stream.GetOutputStreamAt(0)))
        {
            writer.WriteBytes(png);
            await writer.StoreAsync();
        }

        stream.Seek(0);
        await image.SetSourceAsync(stream);
        if (generation != _wifiQrGeneration)
        {
            return;
        }

        WifiQrImage = image;
    }

    private void BindPasswordHistory(IReadOnlyList<PasswordHistoryEntry>? entries)
    {
        PasswordHistory.Clear();
        if (entries is not null)
        {
            for (var i = 0; i < entries.Count; i++)
            {
                var entry = entries[i];
                if (string.IsNullOrEmpty(entry.Password))
                {
                    continue;
                }

                PasswordHistory.Add(new PasswordHistoryRow(entry, CopyPreviousPassword, RestorePreviousPassword));
            }
        }

        OnPropertyChanged(nameof(HasPasswordHistory));
    }

    private void CopyPreviousPassword(PasswordHistoryRow row) => Copy(row.Password);

    private void RestorePreviousPassword(PasswordHistoryRow row)
    {
        EditPassword = row.Password;
        IsPasswordVisible = true;
        SetStatus("RestoredPreviousPassword");
    }

    private void HidePasswordHistory()
    {
        for (var i = 0; i < PasswordHistory.Count; i++)
        {
            PasswordHistory[i].Hide();
        }
    }

    private void ClearMasterFields()
    {
        MasterPassword = string.Empty;
        ConfirmPassword = string.Empty;
        _masterKeyboard.Reset();
        NotifyMasterKeyboard();
    }

    private async void DebounceTotpRestart()
    {
        _totpDebounceCancellation?.Cancel();
        _totpDebounceCancellation?.Dispose();
        _totpDebounceCancellation = new CancellationTokenSource();
        var token = _totpDebounceCancellation.Token;

        try
        {
            await Task.Delay(180, token);
            RestartTotpLoop();
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void RestartTotpLoop()
    {
        StopTotpLoop();
        if (string.IsNullOrWhiteSpace(EditTotpSecret) || !IsUnlocked)
        {
            TotpCode = string.Empty;
            return;
        }

        _totpCancellation = new CancellationTokenSource();
        _ = RunTotpLoopAsync(_totpCancellation.Token);
    }

    private async Task RunTotpLoopAsync(CancellationToken token)
    {
        if (!TotpService.TryDecode(EditTotpSecret, out var key))
        {
            TotpCode = string.Empty;
            return;
        }

        try
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var unix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    var code = TotpService.GetCode(key, unix);
                    var seconds = TotpService.SecondsRemaining();
                    if (TotpCode != code)
                    {
                        TotpCode = code;
                    }

                    if (TotpSecondsLeft != seconds)
                    {
                        TotpSecondsLeft = seconds;
                    }
                }
                catch (Exception)
                {
                    TotpCode = string.Empty;
                    return;
                }

                try
                {
                    await Task.Delay(1000, token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private void StopTotpLoop()
    {
        _totpCancellation?.Cancel();
        _totpCancellation?.Dispose();
        _totpCancellation = null;
        TotpCode = string.Empty;
    }

    private void SchedulePasswordHide()
    {
        CancelPasswordHide();
        _hidePasswordCancellation = new CancellationTokenSource();
        var token = _hidePasswordCancellation.Token;
        _ = HidePasswordLaterAsync(token);
    }

    private async Task HidePasswordLaterAsync(CancellationToken token)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(20), token);
            if (!token.IsCancellationRequested)
            {
                IsPasswordVisible = false;
                HidePasswordHistory();
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void CancelPasswordHide()
    {
        _hidePasswordCancellation?.Cancel();
        _hidePasswordCancellation?.Dispose();
        _hidePasswordCancellation = null;
    }

    private void ClearEditor()
    {
        NewItem(VaultItemKind.Login);
    }

    private void NotifySaveCommand()
    {
        _saveItemCommand.NotifyCanExecuteChanged();
    }

    private void NotifyEditorCommands()
    {
        NotifySaveCommand();
        _deleteItemCommand.NotifyCanExecuteChanged();
        ShareItemCommand.NotifyCanExecuteChanged();
        ShareVaultCommand.NotifyCanExecuteChanged();
        ImportShareCommand.NotifyCanExecuteChanged();
        ImportCsvCommand.NotifyCanExecuteChanged();
        ExportCsvCommand.NotifyCanExecuteChanged();
        ExportPortableCommand.NotifyCanExecuteChanged();
        OpenPortableCommand.NotifyCanExecuteChanged();
        EmergencyKitCommand.NotifyCanExecuteChanged();
        CreateShamirCommand.NotifyCanExecuteChanged();
        NotifyUsbCommands();
        AddAttachmentCommand.NotifyCanExecuteChanged();
        AutofillCommand.NotifyCanExecuteChanged();
        SaveSettingsCommand.NotifyCanExecuteChanged();
        EnableHelloCommand.NotifyCanExecuteChanged();
        ChangeMasterCommand.NotifyCanExecuteChanged();
        GenerateTotpCommand.NotifyCanExecuteChanged();
        GenerateAliasCommand.NotifyCanExecuteChanged();
        CopyRecoveryCodesCommand.NotifyCanExecuteChanged();
    }

    private void NotifyPersonCommands()
    {
        AddPersonCommand.NotifyCanExecuteChanged();
        SwitchPersonCommand.NotifyCanExecuteChanged();
        AddMailboxCommand.NotifyCanExecuteChanged();
        RemoveMailboxCommand.NotifyCanExecuteChanged();
        MakeDefaultMailboxCommand.NotifyCanExecuteChanged();
        RemovePersonCommand.NotifyCanExecuteChanged();
        NotifyPanicCommands();
        OnPropertyChanged(nameof(HasSeveralPeople));
        OnPropertyChanged(nameof(PeopleWarning));
        OnPropertyChanged(nameof(CurrentPersonLabel));
    }

    public void NotifyLanguage()
    {
        RebuildMediaSortChoices();
        RefreshVisibleItems();
        RebuildAuditFilters();
        RefreshHealth();
        NotifyPersonCommands();
        OnPropertyChanged(nameof(HealthSummary));
        OnPropertyChanged(nameof(ClockStatus));
        OnPropertyChanged(nameof(VaultWorkspaceTitle));
        OnPropertyChanged(nameof(FolderFilterHeader));
        OnPropertyChanged(nameof(MediaAddCurrentLabel));
        OnPropertyChanged(nameof(MediaGalleryTitle));
        OnPropertyChanged(nameof(MasterRotationStatus));
        OnPropertyChanged(nameof(MasterRotationOverdue));
        OnPropertyChanged(nameof(MasterRotationSoon));
        OnPropertyChanged(nameof(TotpDisplay));
        OnPropertyChanged(nameof(PasswordRevealLabel));
        OnPropertyChanged(nameof(AutofillHint));
        OnPropertyChanged(nameof(PeopleWarning));
        OnPropertyChanged(nameof(HelloWarning));
        OnPropertyChanged(nameof(RecoveryStatus));
        OnPropertyChanged(nameof(UsbHint));
        OnPropertyChanged(nameof(MailboxWarning));
        OnPropertyChanged(nameof(SwitchWarning));
        OnPropertyChanged(nameof(PanicWarning));
        OnPropertyChanged(nameof(DecoyStatusText));
        OnPropertyChanged(nameof(NameHeader));
        OnPropertyChanged(nameof(NamePlaceholderText));
        OnPropertyChanged(nameof(PasswordFieldHeader));
        OnPropertyChanged(nameof(NotesHeader));
        OnPropertyChanged(nameof(HumanVerificationHeading));
        OnPropertyChanged(nameof(HumanVerificationDetail));
        ApplyDefaultPersonName();
        RefreshUsageLabels();
        foreach (var row in PasswordHistory)
        {
            row.RefreshLanguage();
        }

        if (_statusKey is not null)
        {
            SetStatus(_statusKey, _statusArgs);
        }
    }

    private void OnUiLanguageChanged(object? sender, EventArgs e)
    {
        NotifyLanguage();
    }

    private string ActiveMailboxEmail() =>
        SelectedMailboxProfile?.Email is { Length: > 0 } email ? email : PrimaryEmail;

    private bool CanAddPerson() => !IsBusy && OccupantRules.CanAddOccupant(Occupants.Count) && !string.IsNullOrWhiteSpace(NewPersonName);

    private bool CanAddMailbox() =>
        IsUnlocked && OccupantRules.CanAddMailbox(MailboxProfiles.Count) && !string.IsNullOrWhiteSpace(NewMailboxEmail);

    private async Task AddPersonAsync()
    {
        if (!CanAddPerson())
        {
            return;
        }

        if (IsUnlocked)
        {
            var accepted = ConfirmAsync is not null && await ConfirmAsync(UiStrings.Get("SwitchPerson"), SharedPcGuidance.SwitchLocksMemory, null);
            if (!accepted)
            {
                return;
            }

            Lock();
        }

        IsBusy = true;
        try
        {
            var occupant = await _occupants.AddAsync(NewPersonName);
            NewPersonName = string.Empty;
            RefreshOccupantList();
            await ApplyOccupantAsync(occupant);
            SetStatus("CreateMasterFor", occupant.DisplayName);
        }
        catch (Exception)
        {
            SetStatus("CouldNotAddPerson");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task SwitchSelectedPersonAsync(VaultOccupant? previous)
    {
        if (SelectedOccupant is null)
        {
            return;
        }

        if (previous is not null && previous.Id == SelectedOccupant.Id)
        {
            return;
        }

        if (IsBusy)
        {
            if (previous is not null)
            {
                SelectOccupantQuietly(previous);
            }

            return;
        }

        if (IsUnlocked)
        {
            var accepted = ConfirmAsync is not null && await ConfirmAsync(UiStrings.Get("SwitchPerson"), SharedPcGuidance.SwitchLocksMemory, null);
            if (!accepted)
            {
                if (previous is not null)
                {
                    SelectOccupantQuietly(previous);
                }

                return;
            }
        }

        IsBusy = true;
        try
        {
            await ApplyOccupantAsync(SelectedOccupant);
            SetStatus(NeedsSetup ? "CreateMasterShort" : "UnlockPersonsVault", SelectedOccupant.DisplayName);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ApplyOccupantAsync(VaultOccupant occupant, bool lockVault = true)
    {
        if (lockVault)
        {
            Lock();
        }

        _store.SelectFolder(occupant.FolderName);
        _homeFolderName = occupant.FolderName;
        await _occupants.SetActiveAsync(occupant.Id);
        SelectOccupantQuietly(occupant);
        var probe = await _store.ProbeAsync();
        NeedsSetup = !probe.Exists;
        HelloAvailable = !NeedsSetup && probe.HelloEnabled;
        UsbUnlockAvailable = !NeedsSetup && await _store.UsbUnlockEnabledAsync();
        RecoveryConfigured = !NeedsSetup && await _store.RecoveryConfiguredAsync();
        IsLocked = true;
        NotifyPersonCommands();
    }

    private void SelectOccupantQuietly(VaultOccupant? occupant)
    {
        _loadingOccupants = true;
        try
        {
            _selectedOccupant = occupant;
            OnPropertyChanged(nameof(SelectedOccupant));
            OnPropertyChanged(nameof(CurrentPersonLabel));
            SwitchPersonCommand.NotifyCanExecuteChanged();
        }
        finally
        {
            _loadingOccupants = false;
        }
    }

    private void RefreshOccupantList()
    {
        _loadingOccupants = true;
        Occupants.Clear();
        foreach (var occupant in _occupants.Catalog.Occupants)
        {
            Occupants.Add(occupant);
        }

        NotifyPersonCommands();
    }

    private async Task AddMailboxAsync()
    {
        if (!CanAddMailbox())
        {
            return;
        }

        MailboxProfileService.Migrate(_store.Settings);
        var profile = new MailboxProfile
        {
            Label = string.IsNullOrWhiteSpace(NewMailboxLabel) ? UiStrings.Get("Mailbox") : NewMailboxLabel.Trim(),
            Email = NewMailboxEmail.Trim(),
            IsDefault = _store.Settings.Profiles.Count == 0
        };
        _store.Settings.Profiles.Add(profile);
        NewMailboxEmail = string.Empty;
        await PersistMailboxProfilesAsync(profile.Id, makeSelectedDefault: profile.IsDefault);
        SetStatus("MailboxSavedInside");
    }

    private async Task RemoveSelectedMailboxAsync()
    {
        if (SelectedMailboxProfile is null)
        {
            return;
        }

        MailboxProfileService.Migrate(_store.Settings);
        _store.Settings.Profiles.RemoveAll(profile => profile.Id == SelectedMailboxProfile.Id);
        await PersistMailboxProfilesAsync(null, makeSelectedDefault: false);
    }

    private async Task MakeDefaultMailboxAsync()
    {
        if (SelectedMailboxProfile is null)
        {
            return;
        }

        await PersistMailboxProfilesAsync(SelectedMailboxProfile.Id, makeSelectedDefault: true);
        SetStatus("MailboxNowDefault", SelectedMailboxProfile.Label);
    }

    private async Task RemoveCurrentPersonAsync()
    {
        if (SelectedOccupant is null || !IsUnlocked)
        {
            return;
        }

        var accepted = ConfirmAsync is not null
            && await ConfirmAsync(
                UiStrings.Get("RemovePersonTitle"),
                UiStrings.Format("RemovePersonBody", SelectedOccupant.DisplayName),
                UiStrings.Get("Delete"));
        if (!accepted)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var id = SelectedOccupant.Id;
            await _store.DeleteCurrentFilesAsync();
            await _occupants.RemoveAsync(id);
            RefreshOccupantList();
            var next = _occupants.Active();
            if (next is null)
            {
                SelectOccupantQuietly(null);
                NeedsSetup = true;
                IsLocked = true;
                ApplyDefaultPersonName();
                SetStatus("AllPeopleRemoved");
                return;
            }

            await ApplyOccupantAsync(next);
            SetStatus("RemovedUnlockNext", next.DisplayName);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task ResetAppDataAsync()
    {
        if (IsBusy || _factoryResetPending)
        {
            return;
        }

        if (IsDecoySession || IsPanicDecoySession || IsEditingDecoy)
        {
            if (ConfirmAsync is not null)
            {
                await ConfirmAsync(UiStrings.Get("ResetAppDecoyTitle"), UiStrings.Get("ResetAppDecoyBody"), UiStrings.Get("Continue"));
            }

            return;
        }

        if (!AppResetRules.CanErase(IsUnlocked, decoySession: false) || ConfirmAsync is null || AskLabeledPasswordAsync is null)
        {
            if (ConfirmAsync is not null)
            {
                await ConfirmAsync(UiStrings.Get("ResetAppUnlockTitle"), UiStrings.Get("ResetAppUnlockBody"), UiStrings.Get("Continue"));
            }

            return;
        }

        if (!await ConfirmAsync(UiStrings.Get("ResetAppWarn1Title"), UiStrings.Get("ResetAppWarn1Body"), UiStrings.Get("Continue")))
        {
            return;
        }

        if (!await ConfirmAsync(UiStrings.Get("ResetAppWarn2Title"), UiStrings.Get("ResetAppWarn2Body"), UiStrings.Get("Continue")))
        {
            return;
        }

        if (!await ConfirmAsync(UiStrings.Get("ResetAppWarn3Title"), UiStrings.Get("ResetAppWarn3Body"), UiStrings.Get("ResetAppErase")))
        {
            return;
        }

        var master = await AskLabeledPasswordAsync(
            UiStrings.Get("ResetAppMasterTitle"),
            UiStrings.Get("ResetAppMasterHeader"),
            UiStrings.Get("ResetAppMasterHint"));
        if (master is null)
        {
            SetStatus("ResetAppCancelled");
            return;
        }

        if (!_store.VerifyMasterPassword(master))
        {
            SetStatus("MasterWrongCurrent");
            return;
        }

        _factoryResetPending = true;
        OnPropertyChanged(nameof(IsUnlocked));
        OnPropertyChanged(nameof(ShowWorkspace));
        OnPropertyChanged(nameof(ShowHumanVerification));
        OnPropertyChanged(nameof(HumanVerificationHeading));
        OnPropertyChanged(nameof(HumanVerificationDetail));
        NotifyEditorCommands();
        var bind = RandomNumberGenerator.GetBytes(32);
        BeginHumanVerification(bind);
        VaultPageRequested?.Invoke();
        SetStatus("ResetAppHumanHint");
    }

    private async Task HandleFactoryResetHumanAsync(HumanPresenceSubmitResult result)
    {
        if (result is HumanPresenceSubmitResult.Wrong)
        {
            _humanFailures++;
            PublishHumanUi();
            SetStatus("HumanVerificationWrong");
            if (_humanFailures >= 8)
            {
                AbortFactoryReset("TooManyAttempts");
                Lock("TooManyAttempts");
            }

            return;
        }

        if (result is HumanPresenceSubmitResult.Expired or HumanPresenceSubmitResult.Consumed or HumanPresenceSubmitResult.Invalid)
        {
            AbortFactoryReset("HumanVerificationExpired");
            return;
        }

        PublishHumanUi();
        if (result != HumanPresenceSubmitResult.Completed || _human is null || !_human.TryConsume(out var receipt))
        {
            return;
        }

        receipt.Dispose();
        await ExecuteFactoryResetAsync().ConfigureAwait(true);
    }

    private void AbortFactoryReset(string statusKey)
    {
        _factoryResetPending = false;
        ClearHumanVerification();
        OnPropertyChanged(nameof(IsUnlocked));
        OnPropertyChanged(nameof(ShowWorkspace));
        OnPropertyChanged(nameof(ShowHumanVerification));
        OnPropertyChanged(nameof(HumanVerificationHeading));
        OnPropertyChanged(nameof(HumanVerificationDetail));
        NotifyEditorCommands();
        SetStatus(statusKey);
    }

    private async Task ExecuteFactoryResetAsync()
    {
        IsBusy = true;
        _wipingAppData = true;
        try
        {
            _clipboard.ClearNow();
            ClearHumanSkip();
            var people = _occupants.Catalog.Occupants.ToList();
            Lock();
            foreach (var person in people)
            {
                _store.SelectFolder(person.FolderName);
                await _store.DeleteCurrentFilesAsync().ConfigureAwait(true);
            }

            _decoyStore.SelectFolder(OccupantRules.DecoyFolderName);
            await _decoyStore.DeleteCurrentFilesAsync().ConfigureAwait(true);
            _store.SelectFolder(string.Empty);
            await _store.DeleteCurrentFilesAsync().ConfigureAwait(true);
            await _occupants.ClearAsync().ConfigureAwait(true);
            _preferences.Clear();
            WipeLocalHumanSkip();
            RefreshOccupantList();
            SelectOccupantQuietly(null);
            NeedsSetup = true;
            IsLocked = true;
            _factoryResetPending = false;
            ClearHumanVerification();
            ApplyDefaultPersonName();
            VisibleItems.Clear();
            HealthFindings.Clear();
            AttachmentNames.Clear();
            PasswordHistory.Clear();
            MailboxProfiles.Clear();
            HelloAvailable = false;
            UsbUnlockAvailable = false;
            RecoveryConfigured = false;
            DecoyExists = false;
            OnPropertyChanged(nameof(OpenDecoyOnPanic));
            OnPropertyChanged(nameof(IsUnlocked));
            OnPropertyChanged(nameof(ShowSetup));
            OnPropertyChanged(nameof(ShowUnlock));
            OnPropertyChanged(nameof(ShowWorkspace));
            OnPropertyChanged(nameof(ShowHumanVerification));
            OnPropertyChanged(nameof(HumanVerificationHeading));
            OnPropertyChanged(nameof(HumanVerificationDetail));
            NotifyPersonCommands();
            NotifyEditorCommands();
            FactoryResetCompleted?.Invoke();
            SetStatus("ResetAppDone");
            VaultPageRequested?.Invoke();
        }
        catch (Exception)
        {
            _factoryResetPending = false;
            ClearHumanVerification();
            SetStatus("ResetAppFailed");
        }
        finally
        {
            _wipingAppData = false;
            IsBusy = false;
        }
    }

    private static void WipeLocalHumanSkip()
    {
        try
        {
            HumanPresenceSkipFile.Clear();
            var root = UnvirtualizedPaths.StemRoot();
            if (!Directory.Exists(root))
            {
                return;
            }

            foreach (var path in Directory.GetFileSystemEntries(root))
            {
                var name = Path.GetFileName(path);
                if (!AppResetRules.ShouldWipeStemRootFile(name))
                {
                    continue;
                }

                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
        }
        catch (Exception)
        {
        }
    }

    public async Task PanicLockAsync()
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        try
        {
            _clipboard.ClearNow();
            ClearHumanSkip();
            var openDecoy = OpenDecoyOnPanic && (DecoyExists || await ProbeDecoyExistsAsync());
            if (IsPanicDecoySession && openDecoy)
            {
                PanicCompleted?.Invoke();
                return;
            }

            Lock(openDecoy ? "LockedDefault" : "PanicLocked");
            if (!openDecoy)
            {
                PanicCompleted?.Invoke();
                return;
            }

            try
            {
                await OpenDecoySessionAsync(editMode: false);
            }
            catch (Exception)
            {
                Lock("CouldNotOpenDecoy");
            }

            PanicCompleted?.Invoke();
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task CreateOrReplaceDecoyAsync()
    {
        if (!CanCreateDecoy())
        {
            return;
        }

        var replacing = DecoyExists;
        var accepted = ConfirmAsync is not null
            && await ConfirmAsync(
                UiStrings.Get(replacing ? "ReplaceDecoyTitle" : "CreateDecoyTitle"),
                SharedPcGuidance.PanicIsNotForensics + " " + UiStrings.Get(replacing ? "ReplaceDecoyBody" : "CreateDecoyBody"),
                UiStrings.Get(replacing ? "ReplaceDecoyVault" : "CreateDecoyVault"));
        if (!accepted)
        {
            return;
        }

        IsBusy = true;
        try
        {
            _decoyStore.SelectFolder(OccupantRules.DecoyFolderName);
            if (replacing)
            {
                await _decoyStore.DeleteCurrentFilesAsync();
            }

            var decoyPassword = _secretGenerator.Generate(PasswordOptions.CreateDefault() with { Length = 24 });
            await _decoyStore.CreateAsync(decoyPassword, requireHumanPresence: false);
            foreach (var item in DecoyVaultSeeder.CreateSampleItems(_secretGenerator))
            {
                _decoyStore.Add(item);
            }

            await _decoyStore.SaveAsync();
            await _decoyStore.EnablePanicWrapAsync();
            _decoyStore.Lock();
            DecoyExists = true;
            OpenDecoyOnPanic = true;
            OnPropertyChanged(nameof(OpenDecoyOnPanic));
            SetStatus("DecoyCreated");
        }
        catch (Exception)
        {
            _decoyStore.Lock();
            SetStatus("CouldNotCreateDecoy");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task EditDecoyAsync()
    {
        if (!CanEditDecoy())
        {
            return;
        }

        var accepted = ConfirmAsync is not null
            && await ConfirmAsync(
                UiStrings.Get("EditDecoyTitle"),
                UiStrings.Get("EditDecoyBody") + " " + SharedPcGuidance.PanicIsNotForensics,
                UiStrings.Get("EditDecoyVault"));
        if (!accepted)
        {
            return;
        }

        IsBusy = true;
        try
        {
            Lock();
            await OpenDecoySessionAsync(editMode: true);
        }
        catch (Exception)
        {
            Lock("CouldNotOpenDecoy");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RemoveDecoyAsync()
    {
        if (!CanRemoveDecoy())
        {
            return;
        }

        var accepted = ConfirmAsync is not null
            && await ConfirmAsync(
                UiStrings.Get("RemoveDecoyTitle"),
                UiStrings.Get("RemoveDecoyBody"),
                UiStrings.Get("Delete"));
        if (!accepted)
        {
            return;
        }

        IsBusy = true;
        try
        {
            _decoyStore.SelectFolder(OccupantRules.DecoyFolderName);
            await _decoyStore.DeleteCurrentFilesAsync();
            DecoyExists = false;
            OpenDecoyOnPanic = false;
            OnPropertyChanged(nameof(OpenDecoyOnPanic));
            SetStatus("DecoyRemoved");
        }
        catch (Exception)
        {
            SetStatus("CouldNotCreateDecoy");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task OpenDecoySessionAsync(bool editMode)
    {
        if (SelectedOccupant is not null)
        {
            _homeFolderName = SelectedOccupant.FolderName;
        }

        _store.SelectFolder(OccupantRules.DecoyFolderName);
        var key = await _store.LoadPanicKeyAsync();
        await _store.UnlockImmediateWithKeyAsync(key);
        _isDecoySession = true;
        _isEditingDecoy = editMode;
        OnPropertyChanged(nameof(IsDecoySession));
        OnPropertyChanged(nameof(IsEditingDecoy));
        OnPropertyChanged(nameof(IsPanicDecoySession));
        OnPropertyChanged(nameof(ShowDecoyBanner));
        NotifyPanicCommands();
        NotifyPersonCommands();
        DoneEditingDecoyCommand.NotifyCanExecuteChanged();
        await AfterUnlockAsync();
    }

    private async Task RefreshDecoyExistsAsync()
    {
        DecoyExists = await ProbeDecoyExistsAsync();
    }

    private async Task<bool> ProbeDecoyExistsAsync()
    {
        _decoyStore.SelectFolder(OccupantRules.DecoyFolderName);
        return await _decoyStore.ExistsWithoutCreatingAsync();
    }

    private async Task RestoreHomeProbeAsync()
    {
        var probe = await _store.ProbeAsync();
        NeedsSetup = !probe.Exists;
        HelloAvailable = !NeedsSetup && probe.HelloEnabled;
        UsbUnlockAvailable = !NeedsSetup && await _store.UsbUnlockEnabledAsync();
        RecoveryConfigured = !NeedsSetup && await _store.RecoveryConfiguredAsync();
    }

    private bool CanCreateDecoy() => !IsBusy && !IsDecoySession;

    private bool CanEditDecoy() => !IsBusy && DecoyExists && !IsDecoySession;

    private bool CanRemoveDecoy() => !IsBusy && DecoyExists && !IsDecoySession;

    private void NotifyPanicCommands()
    {
        PanicLockCommand.NotifyCanExecuteChanged();
        ResetAppDataCommand.NotifyCanExecuteChanged();
        CreateDecoyCommand.NotifyCanExecuteChanged();
        EditDecoyCommand.NotifyCanExecuteChanged();
        RemoveDecoyCommand.NotifyCanExecuteChanged();
        DoneEditingDecoyCommand.NotifyCanExecuteChanged();
        EnableHelloCommand.NotifyCanExecuteChanged();
        ChangeMasterCommand.NotifyCanExecuteChanged();
        ImportCsvCommand.NotifyCanExecuteChanged();
        ExportCsvCommand.NotifyCanExecuteChanged();
        ExportPortableCommand.NotifyCanExecuteChanged();
        OpenPortableCommand.NotifyCanExecuteChanged();
    }

    private static int KindIndex(string kind) => kind switch
    {
        VaultItemKind.Alias => 1,
        VaultItemKind.Card => 2,
        VaultItemKind.Note => 3,
        VaultItemKind.Identity => 4,
        VaultItemKind.Recovery => 5,
        VaultItemKind.Wifi => 6,
        VaultItemKind.Secret => 7,
        _ => 0
    };

    private static string KindFromIndex(int index) => index switch
    {
        1 => VaultItemKind.Alias,
        2 => VaultItemKind.Card,
        3 => VaultItemKind.Note,
        4 => VaultItemKind.Identity,
        5 => VaultItemKind.Recovery,
        6 => VaultItemKind.Wifi,
        7 => VaultItemKind.Secret,
        _ => VaultItemKind.Login
    };

    private bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    private sealed record PendingLogin(string Password, string Title, string Url, string Username);

    private sealed record PendingSeal(string Name, byte[] Data);
}
