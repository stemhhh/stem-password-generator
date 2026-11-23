using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using StemPasswordGenerator.Services;

namespace StemPasswordGenerator.ViewModels;

public sealed class CipherViewModel : INotifyPropertyChanged
{
    private readonly ClipboardService _clipboard;
    private readonly RelayCommand _runCommand;
    private readonly RelayCommand _swapCommand;
    private readonly RelayCommand _copySourceCommand;
    private readonly RelayCommand _copyResultCommand;
    private readonly RelayCommand _clearSourceCommand;
    private readonly RelayCommand _clearCommand;

    private string _source = string.Empty;
    private string _result = string.Empty;
    private string _password = string.Empty;
    private string _confirmPassword = string.Empty;
    private int _algorithmIndex;
    private int _languageIndex;
    private bool _encryptMode = true;
    private bool _busy;
    private bool _writingSource;
    private bool _writingResult;
    private string _status = string.Empty;
    private string? _statusKey;
    private byte[]? _lastBlob;
    private int _runId;

    public CipherViewModel(ClipboardService clipboard)
    {
        _clipboard = clipboard ?? throw new ArgumentNullException(nameof(clipboard));
        _runCommand = new RelayCommand(() => _ = RunAsync(), CanRun);
        _swapCommand = new RelayCommand(Swap, () => CanEdit);
        _copySourceCommand = new RelayCommand(CopySource, () => CanEdit && !string.IsNullOrEmpty(SourceText));
        _copyResultCommand = new RelayCommand(CopyResult, () => CanEdit && !string.IsNullOrEmpty(ResultText));
        _clearSourceCommand = new RelayCommand(ClearBoards, () => CanEdit && HasBoardText);
        _clearCommand = new RelayCommand(Clear, () => HasAnyField && CanEdit);
        RunCommand = _runCommand;
        SwapCommand = _swapCommand;
        CopySourceCommand = _copySourceCommand;
        CopyResultCommand = _copyResultCommand;
        ClearSourceCommand = _clearSourceCommand;
        ClearCommand = _clearCommand;
        UiStrings.LanguageChanged += OnLanguageChanged;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public RelayCommand RunCommand { get; }

    public RelayCommand SwapCommand { get; }

    public RelayCommand CopySourceCommand { get; }

    public RelayCommand CopyResultCommand { get; }

    public RelayCommand ClearSourceCommand { get; }

    public RelayCommand ClearCommand { get; }

    public bool IsEncryptMode
    {
        get => _encryptMode;
        set
        {
            if (_encryptMode == value)
            {
                return;
            }

            _encryptMode = value;
            if (_encryptMode)
            {
                PrefillConfirm();
            }

            NotifyDirection();
            NotifyCommands();
        }
    }

    public bool CanEdit => !IsBusy;

    public string SourceText
    {
        get => _source;
        set => SetEditableText(ref _source, value, invalidateResult: !_writingSource);
    }

    public string ResultText
    {
        get => _result;
        set => SetEditableText(ref _result, value, invalidateResult: false);
    }

    public string Password
    {
        get => _password;
        set
        {
            SetEditableText(ref _password, value, invalidateResult: true);
            OnPropertyChanged(nameof(PasswordHint));
            OnPropertyChanged(nameof(ConfirmHint));
        }
    }

    public string ConfirmPassword
    {
        get => _confirmPassword;
        set
        {
            SetEditableText(ref _confirmPassword, value, invalidateResult: false);
            OnPropertyChanged(nameof(ConfirmHint));
        }
    }

    public int AlgorithmIndex
    {
        get => _algorithmIndex;
        set
        {
            var clamped = Math.Clamp(value, 0, 1);
            if (_algorithmIndex == clamped)
            {
                return;
            }

            _algorithmIndex = clamped;
            OnPropertyChanged();
            InvalidateCiphertext();
        }
    }

    public int LanguageIndex
    {
        get => _languageIndex;
        set
        {
            var clamped = Math.Clamp(value, 0, 2);
            if (_languageIndex == clamped)
            {
                return;
            }

            _languageIndex = clamped;
            OnPropertyChanged();
            ShowCachedBlob();
        }
    }

    public bool IsBusy
    {
        get => _busy;
        private set
        {
            if (_busy == value)
            {
                return;
            }

            _busy = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanEdit));
            NotifyCommands();
        }
    }

    public string Status
    {
        get => _status;
        private set
        {
            if (_status == value)
            {
                return;
            }

            _status = value;
            OnPropertyChanged();
        }
    }

    public string PasswordHint
    {
        get
        {
            if (string.IsNullOrEmpty(Password))
            {
                return string.Empty;
            }

            var key = TextCipher.PasswordIssueKey(Password);
            return key is null ? string.Empty : UiStrings.Get(key);
        }
    }

    public string ConfirmHint =>
        IsEncryptMode
        && !string.IsNullOrEmpty(ConfirmPassword)
        && !SecretsMatch(Password, ConfirmPassword)
            ? UiStrings.Get("CipherPasswordMismatch")
            : string.Empty;

    public string SourceTitle => UiStrings.Get(IsEncryptMode ? "CipherPlainTitle" : "CipherCipherTitle");

    public string ResultTitle => UiStrings.Get(IsEncryptMode ? "CipherCipherTitle" : "CipherPlainTitle");

    public string SourcePlaceholder => UiStrings.Get(IsEncryptMode ? "CipherSourcePlaceholderEncrypt" : "CipherSourcePlaceholderDecrypt");

    public string ResultPlaceholder => UiStrings.Get(IsEncryptMode ? "CipherResultPlaceholderEncrypt" : "CipherResultPlaceholderDecrypt");

    public string RunLabel => UiStrings.Get(IsEncryptMode ? "CipherEncrypt" : "CipherDecrypt");

    private TextCipherAlgorithm Algorithm =>
        AlgorithmIndex == 1 ? TextCipherAlgorithm.ChaCha20Poly1305 : TextCipherAlgorithm.Aes256Gcm;

    private TextCipherLanguage Language => LanguageIndex switch
    {
        1 => TextCipherLanguage.Hex,
        2 => TextCipherLanguage.Binary,
        _ => TextCipherLanguage.Base64
    };

    private bool HasBoardText => !string.IsNullOrEmpty(SourceText) || !string.IsNullOrEmpty(ResultText);

    private bool HasAnyField =>
        HasBoardText
        || !string.IsNullOrEmpty(Password)
        || !string.IsNullOrEmpty(ConfirmPassword)
        || !string.IsNullOrEmpty(Status);

    private bool CanRun()
    {
        if (!CanEdit || string.IsNullOrWhiteSpace(SourceText) || TextCipher.PasswordIssueKey(Password) is not null)
        {
            return false;
        }

        return !IsEncryptMode || SecretsMatch(Password, ConfirmPassword);
    }

    private async Task RunAsync()
    {
        if (IsEncryptMode)
        {
            await EncryptAsync().ConfigureAwait(true);
        }
        else
        {
            await DecryptAsync().ConfigureAwait(true);
        }
    }

    private async Task EncryptAsync()
    {
        if (string.IsNullOrWhiteSpace(SourceText))
        {
            SetStatus("CipherNeedText");
            return;
        }

        if (TextCipher.PasswordIssueKey(Password) is { } passwordKey)
        {
            SetStatus(passwordKey);
            return;
        }

        if (!SecretsMatch(Password, ConfirmPassword))
        {
            SetStatus("CipherPasswordMismatch");
            return;
        }

        if (!TextCipher.IsSupported(Algorithm))
        {
            SetStatus("CipherAlgUnavailable");
            return;
        }

        if (Encoding.UTF8.GetByteCount(SourceText) > TextCipher.MaximumPlaintextBytes)
        {
            SetStatus("CipherTooLarge");
            return;
        }

        var runId = ++_runId;
        IsBusy = true;
        SetStatus("CipherWorking");
        var plaintext = SourceText;
        var password = Password;
        var algorithm = Algorithm;
        var language = Language;
        try
        {
            var blob = await Task.Run(() => TextCipher.EncryptToBlob(plaintext, password, algorithm)).ConfigureAwait(true);
            if (runId != _runId)
            {
                CryptographicOperations.ZeroMemory(blob);
                return;
            }

            ReplaceBlob(blob);
            WriteResult(TextCipher.Encode(blob, language));
            SetStatus("CipherEncrypted");
        }
        catch (ArgumentException)
        {
            SetStatus("CipherTooLarge");
        }
        catch (Exception)
        {
            SetStatus("CipherFailed");
        }
        finally
        {
            if (runId == _runId)
            {
                IsBusy = false;
            }
        }
    }

    private async Task DecryptAsync()
    {
        if (string.IsNullOrWhiteSpace(SourceText))
        {
            SetStatus("CipherNeedCipher");
            return;
        }

        if (TextCipher.PasswordIssueKey(Password) is { } passwordKey)
        {
            SetStatus(passwordKey);
            return;
        }

        var runId = ++_runId;
        IsBusy = true;
        SetStatus("CipherWorking");
        var encoded = SourceText;
        var password = Password;
        try
        {
            var result = await Task.Run(() =>
            {
                var text = TextCipher.Decrypt(encoded, password, out var blob);
                return (text, blob);
            }).ConfigureAwait(true);
            if (runId != _runId)
            {
                CryptographicOperations.ZeroMemory(result.blob);
                return;
            }

            ReplaceBlob(result.blob);
            LanguageIndex = (int)TextCipher.DetectLanguage(encoded);
            WriteResult(result.text);
            SetStatus("CipherDecrypted");
        }
        catch (CryptographicException)
        {
            if (runId == _runId)
            {
                DiscardBlob();
                SetStatus("CipherWrongPassword");
            }
        }
        catch (Exception)
        {
            if (runId == _runId)
            {
                DiscardBlob();
                SetStatus("CipherFailed");
            }
        }
        finally
        {
            if (runId == _runId)
            {
                IsBusy = false;
            }
        }
    }

    private void Swap()
    {
        _runId++;
        DiscardBlob();
        _encryptMode = !_encryptMode;
        WriteSource(string.Empty);
        WriteResult(string.Empty);
        if (_encryptMode)
        {
            PrefillConfirm();
        }

        NotifyDirection();
        NotifyCommands();
        SetStatus("CipherSwapped");
    }

    private void CopySource()
    {
        if (_clipboard.TryCopy(SourceText))
        {
            SetStatus(IsEncryptMode ? "CipherCopiedPlain" : "CipherCopiedCipher");
        }
    }

    private void CopyResult()
    {
        if (_clipboard.TryCopy(ResultText))
        {
            SetStatus(IsEncryptMode ? "CipherCopiedCipher" : "CipherCopiedPlain");
        }
    }

    private void ClearBoards()
    {
        _runId++;
        DiscardBlob();
        WriteSource(string.Empty);
        WriteResult(string.Empty);
        SetStatus("CipherCleared");
    }

    public void ResetSession() => Clear();

    private void Clear()
    {
        ClearBoards();
        Password = string.Empty;
        ConfirmPassword = string.Empty;
        IsEncryptMode = true;
        SetStatus("CipherCleared");
    }

    private void ShowCachedBlob()
    {
        if (_lastBlob is null)
        {
            return;
        }

        var encoded = TextCipher.Encode(_lastBlob, Language);
        if (IsEncryptMode)
        {
            WriteResult(encoded);
        }
        else
        {
            WriteSource(encoded);
        }
    }

    private void InvalidateCiphertext()
    {
        _runId++;
        DiscardBlob();
        if (!_writingResult && !string.IsNullOrEmpty(_result) && IsEncryptMode)
        {
            WriteResult(string.Empty);
        }
    }

    private void PrefillConfirm()
    {
        if (string.IsNullOrEmpty(_confirmPassword) && !string.IsNullOrEmpty(_password))
        {
            ConfirmPassword = _password;
        }
    }

    private void WriteSource(string value)
    {
        _writingSource = true;
        try
        {
            SourceText = value;
        }
        finally
        {
            _writingSource = false;
        }
    }

    private void WriteResult(string value)
    {
        _writingResult = true;
        try
        {
            ResultText = value;
        }
        finally
        {
            _writingResult = false;
        }
    }

    private void ReplaceBlob(byte[] blob)
    {
        if (ReferenceEquals(_lastBlob, blob))
        {
            return;
        }

        DiscardBlob();
        _lastBlob = blob;
    }

    private void DiscardBlob()
    {
        if (_lastBlob is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_lastBlob);
        _lastBlob = null;
    }

    private void SetEditableText(ref string field, string value, bool invalidateResult, [CallerMemberName] string? propertyName = null)
    {
        value ??= string.Empty;
        if (field == value)
        {
            return;
        }

        field = value;
        if (invalidateResult)
        {
            InvalidateCiphertext();
        }

        OnPropertyChanged(propertyName);
        NotifyCommands();
    }

    private void NotifyDirection()
    {
        OnPropertyChanged(nameof(IsEncryptMode));
        OnPropertyChanged(nameof(SourceTitle));
        OnPropertyChanged(nameof(ResultTitle));
        OnPropertyChanged(nameof(SourcePlaceholder));
        OnPropertyChanged(nameof(ResultPlaceholder));
        OnPropertyChanged(nameof(RunLabel));
        OnPropertyChanged(nameof(ConfirmHint));
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        NotifyDirection();
        OnPropertyChanged(nameof(PasswordHint));
        if (_statusKey is { } key)
        {
            SetStatus(key);
        }
    }

    private void SetStatus(string key)
    {
        _statusKey = key;
        Status = UiStrings.Get(key);
        NotifyCommands();
    }

    private void NotifyCommands()
    {
        _runCommand.NotifyCanExecuteChanged();
        _swapCommand.NotifyCanExecuteChanged();
        _copySourceCommand.NotifyCanExecuteChanged();
        _copyResultCommand.NotifyCanExecuteChanged();
        _clearSourceCommand.NotifyCanExecuteChanged();
        _clearCommand.NotifyCanExecuteChanged();
    }

    private static bool SecretsMatch(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        try
        {
            return leftBytes.Length == rightBytes.Length
                && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
