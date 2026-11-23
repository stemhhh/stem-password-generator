using System.Security.Cryptography;
using StemPasswordGenerator.Helpers;
using StemPasswordGenerator.Models;
using Windows.Storage;

namespace StemPasswordGenerator.Services;

public sealed class VaultStore : IDisposable
{
    private const string FileName = "vault.spg";
    private const string TempFileName = "vault.spg.tmp";
    private const string HelloFileName = "hello.spg";
    private const string PanicFileName = "panic.spg";
    private const string UsbFileName = "usb.spg";
    private const string RecoveryFileName = VaultRecovery.VerifierFileName;
    private const string PendingAuditFileName = "audit.pending";
    private const int MaximumPendingAuditLength = 64 * 1024;
    private const int MaximumFileLength = VaultCryptography.MaximumBlobLength + 256;
    private const int MaximumAttachmentBytes = VaultItemRules.MaximumAttachmentBytes;

    private static readonly byte[] WrapEntropy = System.Text.Encoding.UTF8.GetBytes("StemPasswordGenerator.Vault.v1");
    private static readonly byte[] AuditPendingEntropy = System.Text.Encoding.UTF8.GetBytes("StemPasswordGenerator.AuditPending.v1");
    private static readonly byte[] RecoveryHelloMagic = "SRH1"u8.ToArray();
    private static readonly byte[] RecoveryHelloEntropy = System.Text.Encoding.UTF8.GetBytes("StemPasswordGenerator.Recovery.v1");

    private readonly VaultCryptography _crypto = new();
    private VaultDocument _document = new();
    private VaultKey? _sessionKey;
    private VaultAccessState _access = VaultAccessState.Locked;
    private byte[]? _pendingBind;
    private PendingVaultHold? _pendingHold;
    private DateTimeOffset _pendingExpires;
    private bool _pendingFreshVault;
    private byte[]? _mediaKey;
    private string _folderName = string.Empty;
    private StorageFolder? _cachedFolder;
    private bool? _existsCache;
    private bool? _helloCache;
    private bool? _recoveryCache;
    private byte[]? _recoveryMac;
    private bool _recoveryMacBound;

    public bool IsUnlocked =>
        _access == VaultAccessState.Unlocked
        && _sessionKey is not null
        && !_sessionKey.IsDisposed;

    public bool IsPendingHumanVerification =>
        _access == VaultAccessState.PendingHumanVerification
        && _sessionKey is not null
        && !_sessionKey.IsDisposed;

    public VaultAccessState AccessState => _access;

    public string FolderName => _folderName;

    public IReadOnlyList<VaultItem> Items => _document.Items;

    public IReadOnlyList<MediaEntry> Media => _document.Media;

    public IReadOnlyList<AuditEvent> Audit => _document.Audit;

    public VaultSettings Settings => _document.Settings;

    public void SelectFolder(string folderName)
    {
        Lock();
        var next = folderName ?? string.Empty;
        if (!OccupantRules.IsSafeFolderName(next))
        {
            next = OccupantRules.FolderName(Guid.Empty);
        }

        if (!string.Equals(_folderName, next, StringComparison.Ordinal))
        {
            _cachedFolder = null;
            _existsCache = null;
            _helloCache = null;
            _recoveryCache = null;
        }

        _folderName = next;
    }

    public async Task<bool> ExistsAsync()
    {
        if (_existsCache is bool cached)
        {
            return cached;
        }

        var folder = await GetFolderAsync().ConfigureAwait(true);
        var exists = (await folder.TryGetItemAsync(FileName)) is not null;
        _existsCache = exists;
        return exists;
    }

    public async Task<bool> ExistsWithoutCreatingAsync()
    {
        var root = ApplicationData.Current.LocalFolder;
        StorageFolder folder = root;
        if (!string.IsNullOrWhiteSpace(_folderName))
        {
            if (!OccupantRules.IsSafeFolderName(_folderName))
            {
                _existsCache = false;
                return false;
            }

            foreach (var part in _folderName.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries))
            {
                if (part is "." or "..")
                {
                    continue;
                }

                if (await folder.TryGetItemAsync(part) is not StorageFolder next)
                {
                    _existsCache = false;
                    return false;
                }

                folder = next;
            }
        }

        var exists = await folder.TryGetItemAsync(FileName) is not null;
        _existsCache = exists;
        return exists;
    }

    public async Task<(bool Exists, bool HelloEnabled)> ProbeAsync()
    {
        if (_existsCache is bool existsCached && _helloCache is bool helloCached)
        {
            return (existsCached, helloCached);
        }

        var folder = await GetFolderAsync().ConfigureAwait(true);
        var vaultItem = folder.TryGetItemAsync(FileName);
        var helloItem = folder.TryGetItemAsync(HelloFileName);
        var exists = (await vaultItem) is not null;
        var hello = (await helloItem) is not null;
        _existsCache = exists;
        _helloCache = hello;
        return (exists, hello);
    }

    public async Task<byte[]> CreateAsync(string masterPassword, bool requireHumanPresence = true)
    {
        VaultCryptography.EnsureMasterPassword(masterPassword);
        DisposeSession();
        DiscardPendingHold();
        _document = new VaultDocument();
        _document.Settings.MasterChangedUtc = DateTimeOffset.UtcNow;
        _sessionKey = await Task.Run(() => _crypto.CreateKey(masterPassword)).ConfigureAwait(true);
        _access = VaultAccessState.Unlocked;
        await PersistAsync().ConfigureAwait(true);
        _existsCache = true;
        if (!requireHumanPresence)
        {
            return [];
        }

        return EnterPending(freshVault: true);
    }

    public Task<byte[]> UnlockAsync(string masterPassword) => AuthenticateMasterAsync(masterPassword);

    public async Task<byte[]> AuthenticateMasterAsync(string masterPassword)
    {
        var inner = await ReadInnerBlobAsync().ConfigureAwait(true);
        var result = await Task.Run(() =>
        {
            var document = _crypto.Decrypt(inner, masterPassword, out var key);
            return (document, key);
        }).ConfigureAwait(true);

        DisposeSession();
        DiscardPendingHold();
        _document = new VaultDocument();
        _sessionKey = result.key;
        _pendingHold = new PendingVaultHold(result.document);
        CryptographicOperations.ZeroMemory(inner);
        return EnterPending(freshVault: false);
    }

    public async Task<byte[]> AuthenticateWithKeyAsync(VaultKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var inner = await ReadInnerBlobAsync().ConfigureAwait(true);
        try
        {
            var document = await Task.Run(() => _crypto.Decrypt(inner, key)).ConfigureAwait(true);
            DisposeSession();
            DiscardPendingHold();
            _document = new VaultDocument();
            _sessionKey = key;
            _pendingHold = new PendingVaultHold(document);
            return EnterPending(freshVault: false);
        }
        catch
        {
            key.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inner);
        }
    }

    public async Task UnlockImmediateWithKeyAsync(VaultKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var inner = await ReadInnerBlobAsync().ConfigureAwait(true);
        try
        {
            var document = await Task.Run(() => _crypto.Decrypt(inner, key)).ConfigureAwait(true);
            DisposeSession();
            DiscardPendingHold();
            _document = document;
            _sessionKey = key;
            _access = VaultAccessState.Unlocked;
            LoadMediaKey();
        }
        catch
        {
            key.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inner);
        }
    }

    public async Task UnlockWithKeyAsync(VaultKey key) => await AuthenticateWithKeyAsync(key).ConfigureAwait(true);

    public Task RevealAfterHumanAsync(HumanPresenceReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        if (_access != VaultAccessState.PendingHumanVerification
            || _sessionKey is null
            || _sessionKey.IsDisposed
            || _pendingBind is null
            || DateTimeOffset.UtcNow > _pendingExpires)
        {
            receipt.Dispose();
            Lock();
            throw new InvalidOperationException("Human verification expired.");
        }

        if (!receipt.Matches(_pendingBind))
        {
            receipt.Dispose();
            Lock();
            throw new InvalidOperationException("Human verification failed.");
        }

        receipt.Dispose();
        CryptographicOperations.ZeroMemory(_pendingBind);
        _pendingBind = null;

        if (_pendingFreshVault)
        {
            DiscardPendingHold();
            _pendingFreshVault = false;
            _access = VaultAccessState.Unlocked;
            LoadMediaKey();
            return Task.CompletedTask;
        }

        if (_pendingHold is null || !_pendingHold.HasPayload)
        {
            Lock();
            throw new InvalidOperationException("Human verification expired.");
        }

        _document = _pendingHold.Take();
        DiscardPendingHold();
        _access = VaultAccessState.Unlocked;
        LoadMediaKey();
        return Task.CompletedTask;
    }

    public async Task SaveAsync()
    {
        if (!IsUnlocked)
        {
            throw new InvalidOperationException("The vault is locked.");
        }

        await PersistAsync().ConfigureAwait(true);
    }

    public bool VerifyMasterPassword(string masterPassword)
    {
        EnsureUnlocked();
        return VaultCryptography.Matches(masterPassword, _sessionKey!);
    }

    public void Lock()
    {
        _access = VaultAccessState.Locked;
        _pendingFreshVault = false;
        _pendingExpires = default;
        if (_pendingBind is not null)
        {
            CryptographicOperations.ZeroMemory(_pendingBind);
            _pendingBind = null;
        }

        DiscardPendingHold();
        VaultCryptography.ClearDocument(_document);
        _document = new VaultDocument();
        _recoveryMacBound = false;
        if (_recoveryMac is not null)
        {
            CryptographicOperations.ZeroMemory(_recoveryMac);
            _recoveryMac = null;
        }

        DisposeSession();
    }

    public VaultItem? Find(Guid id) => _document.Items.Find(item => item.Id == id);

    public VaultItem Add(VaultItem item)
    {
        item.Id = item.Id == Guid.Empty ? Guid.NewGuid() : item.Id;
        if (item.CreatedUtc.Year < 2000)
        {
            item.CreatedUtc = DateTimeOffset.UtcNow;
        }

        if (item.ModifiedUtc.Year < 2000)
        {
            item.ModifiedUtc = item.CreatedUtc;
        }

        item.PasswordChangedUtc ??= item.CreatedUtc;
        _document.Items.Insert(0, item);
        return item;
    }

    public void Update(VaultItem item)
    {
        var index = _document.Items.FindIndex(existing => existing.Id == item.Id);
        if (index < 0)
        {
            Add(item);
            return;
        }

        if (item.ModifiedUtc.Year < 2000)
        {
            item.ModifiedUtc = DateTimeOffset.UtcNow;
        }

        _document.Items[index] = item;
    }

    public bool Touch(Guid id, DateTimeOffset usedUtc, string? method = null)
    {
        usedUtc = usedUtc.ToUniversalTime();
        var item = Find(id);
        if (item is not null)
        {
            if (item.LastUsedUtc is { } previous && previous > usedUtc)
            {
                return false;
            }

            item.LastUsedUtc = usedUtc;
            AppendAudit(AuditKind.Used, string.IsNullOrWhiteSpace(method) ? AuditMethod.Copy : method, item.Title, item.Kind, item.Id, usedUtc);
            return true;
        }

        var media = FindMedia(id);
        if (media is null)
        {
            return false;
        }

        if (media.LastUsedUtc is { } last && last > usedUtc)
        {
            return false;
        }

        media.LastUsedUtc = usedUtc;
        AppendAudit(AuditKind.Used, string.IsNullOrWhiteSpace(method) ? AuditMethod.Copy : method, media.Title, media.Category, media.Id, usedUtc);
        return true;
    }

    public void AppendAudit(string kind, string method, string? title = null, string? itemKind = null, Guid? itemId = null, DateTimeOffset? utc = null)
    {
        EnsureUnlocked();
        _document.Audit ??= [];
        AuditRules.Append(_document.Audit, new AuditEvent
        {
            Utc = utc ?? DateTimeOffset.UtcNow,
            Kind = kind,
            Method = method,
            Title = title ?? string.Empty,
            ItemKind = itemKind ?? string.Empty,
            ItemId = itemId
        });
    }

    public async Task RecordLockedFailureAsync(DateTimeOffset utc, string method)
    {
        if (string.IsNullOrWhiteSpace(_folderName) || !OccupantRules.IsSafeFolderName(_folderName))
        {
            return;
        }

        var folder = await GetFolderAsync().ConfigureAwait(true);
        var pending = await ReadPendingAuditAsync(folder).ConfigureAwait(true);
        AuditRules.AppendFail(pending, utc, method);
        await WritePendingAuditAsync(folder, pending).ConfigureAwait(true);
    }

    public async Task AbsorbPendingFailuresAsync()
    {
        EnsureUnlocked();
        var folder = await GetFolderAsync().ConfigureAwait(true);
        var pending = await ReadPendingAuditAsync(folder).ConfigureAwait(true);
        if (pending.Count > 0)
        {
            _document.Audit ??= [];
            AuditRules.Merge(_document.Audit, pending);
        }
    }

    public async Task DiscardPendingFailuresAsync()
    {
        var folder = await GetFolderAsync().ConfigureAwait(true);
        await DeletePendingAuditAsync(folder).ConfigureAwait(true);
    }

    public void Delete(Guid id)
    {
        var existing = Find(id);
        if (existing is not null)
        {
            existing.Password = string.Empty;
            existing.Notes = string.Empty;
            existing.Username = string.Empty;
            if (existing.PasswordHistory is not null)
            {
                for (var i = 0; i < existing.PasswordHistory.Count; i++)
                {
                    existing.PasswordHistory[i].Password = string.Empty;
                }

                existing.PasswordHistory.Clear();
            }
        }

        _document.Items.RemoveAll(item => item.Id == id);
    }

    public void UpdateSettings(VaultSettings settings)
    {
        _document.Settings = settings ?? new VaultSettings();
    }

    public byte[] ExportItems(IEnumerable<Guid> ids, string sharePassword)
    {
        EnsureUnlocked();
        var selected = ids.ToHashSet();
        var document = new VaultDocument
        {
            Version = 2,
            Items = _document.Items
                .Where(item => selected.Contains(item.Id))
                .Select(CloneItem)
                .ToList()
        };
        return _crypto.Encrypt(document, sharePassword);
    }

    public byte[] ExportAll(string sharePassword)
    {
        EnsureUnlocked();
        var document = new VaultDocument
        {
            Version = 2,
            Settings = new VaultSettings
            {
                PrimaryEmail = _document.Settings.PrimaryEmail,
                AliasDomain = _document.Settings.AliasDomain,
                Mailboxes = [.. _document.Settings.Mailboxes],
                Profiles = _document.Settings.Profiles.Select(profile => new MailboxProfile
                {
                    Id = profile.Id,
                    Label = profile.Label,
                    Email = profile.Email,
                    IsDefault = profile.IsDefault
                }).ToList()
            },
            Items = _document.Items.Select(CloneItem).ToList()
        };
        return _crypto.Encrypt(document, sharePassword);
    }

    public byte[] ExportWithSessionKey(IEnumerable<Guid> ids)
    {
        EnsureUnlocked();
        if (_sessionKey is null)
        {
            throw new InvalidOperationException("The vault is locked.");
        }

        var selected = ids.ToHashSet();
        var document = new VaultDocument
        {
            Version = 2,
            Items = _document.Items
                .Where(item => selected.Contains(item.Id))
                .Select(CloneItem)
                .ToList()
        };
        return _crypto.Encrypt(document, _sessionKey);
    }

    public byte[] ExportPortable()
    {
        EnsureUnlocked();
        if (_sessionKey is null)
        {
            throw new InvalidOperationException("The vault is locked.");
        }

        var document = new VaultDocument
        {
            Version = 2,
            Settings = new VaultSettings
            {
                PrimaryEmail = _document.Settings.PrimaryEmail,
                AliasDomain = _document.Settings.AliasDomain,
                Mailboxes = [.. _document.Settings.Mailboxes],
                Profiles = _document.Settings.Profiles.Select(profile => new MailboxProfile
                {
                    Id = profile.Id,
                    Label = profile.Label,
                    Email = profile.Email,
                    IsDefault = profile.IsDefault
                }).ToList()
            },
            Items = _document.Items.Select(CloneItem).ToList()
        };
        var inner = _crypto.Encrypt(document, _sessionKey);
        try
        {
            return PortableVaultFile.Pack(inner);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inner);
        }
    }

    public async Task<byte[]> InstallPortableAsync(byte[] packed, string masterPassword)
    {
        ArgumentNullException.ThrowIfNull(packed);
        VaultCryptography.EnsureMasterPassword(masterPassword);
        if (await ExistsWithoutCreatingAsync().ConfigureAwait(true))
        {
            throw new InvalidOperationException("PortableTargetHasVault");
        }

        if (PortableVaultFile.LooksLikeDpapi(packed))
        {
            throw new InvalidOperationException("PortableIsDpapi");
        }

        if (!PortableVaultFile.TryReadInner(packed, out var inner))
        {
            throw new InvalidOperationException("PortableUnrecognized");
        }

        VaultDocument document;
        VaultKey key;
        try
        {
            var opened = await Task.Run(() =>
            {
                var vault = _crypto.Decrypt(inner, masterPassword, out var session);
                return (vault, session);
            }).ConfigureAwait(true);
            document = opened.vault;
            key = opened.session;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(inner);
            throw;
        }

        try
        {
            var wrapped = WrapForThisUser(inner);
            CryptographicOperations.ZeroMemory(inner);
            inner = [];
            var folder = await GetFolderAsync().ConfigureAwait(true);
            var temp = await folder.CreateFileAsync(TempFileName, CreationCollisionOption.ReplaceExisting);
            await FileIO.WriteBytesAsync(temp, wrapped);
            CryptographicOperations.ZeroMemory(wrapped);
            var destination = await folder.CreateFileAsync(FileName, CreationCollisionOption.OpenIfExists);
            await temp.MoveAndReplaceAsync(destination);
            _existsCache = true;

            DisposeSession();
            DiscardPendingHold();
            _document = new VaultDocument();
            _sessionKey = key;
            _pendingHold = new PendingVaultHold(document);
            return EnterPending(freshVault: false);
        }
        catch
        {
            key.Dispose();
            VaultCryptography.ClearDocument(document);
            throw;
        }
    }

    public bool TryImportWithSessionKey(byte[] blob, out int added)
    {
        added = 0;
        EnsureUnlocked();
        if (_sessionKey is null)
        {
            return false;
        }

        try
        {
            var incoming = _crypto.Decrypt(blob, _sessionKey);
            foreach (var item in incoming.Items)
            {
                item.Id = Guid.NewGuid();
                Add(item);
                added++;
            }

            return added > 0;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public int ImportShare(byte[] blob, string sharePassword)
    {
        EnsureUnlocked();
        var incoming = _crypto.Decrypt(blob, sharePassword);
        var added = 0;
        foreach (var item in incoming.Items)
        {
            item.Id = Guid.NewGuid();
            Add(item);
            added++;
        }

        return added;
    }

    public async Task EnableHelloAsync()
    {
        await WriteKeyWrapAsync(HelloFileName).ConfigureAwait(true);
        _helloCache = true;
    }

    public async Task EnablePanicWrapAsync()
    {
        await WriteKeyWrapAsync(PanicFileName).ConfigureAwait(true);
    }

    public async Task<bool> HelloEnabledAsync()
    {
        if (_helloCache is bool cached)
        {
            return cached;
        }

        var folder = await GetFolderAsync().ConfigureAwait(true);
        var enabled = (await folder.TryGetItemAsync(HelloFileName)) is not null;
        _helloCache = enabled;
        return enabled;
    }

    public async Task DisableHelloAsync()
    {
        var folder = await GetFolderAsync().ConfigureAwait(true);
        if (await folder.TryGetItemAsync(HelloFileName) is StorageFile file)
        {
            await file.DeleteAsync();
        }

        _helloCache = false;
    }

    public async Task<VaultKey> LoadHelloKeyAsync() => await LoadKeyWrapAsync(HelloFileName).ConfigureAwait(true);

    public async Task<bool> RecoveryConfiguredAsync()
    {
        if (_recoveryCache is bool cached)
        {
            return cached;
        }

        var folder = await GetFolderAsync().ConfigureAwait(true);
        var enabled = (await folder.TryGetItemAsync(RecoveryFileName)) is not null;
        _recoveryCache = enabled;
        return enabled;
    }

    public async Task SaveRecoveryVerifierAsync(RecoveryMaterials materials)
    {
        EnsureUnlocked();
        ArgumentNullException.ThrowIfNull(materials);
        var verifier = await Task.Run(() => VaultRecovery.CreateVerifier(materials)).ConfigureAwait(true);
        var blob = VaultRecovery.SerializeVerifier(verifier);
        var keyBytes = _sessionKey!.CopyKeyBytes();
        try
        {
            _recoveryMac = VaultRecovery.MacVerifier(blob, keyBytes);
            _recoveryMacBound = true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }

        var payload = WrapForThisUser(blob);
        CryptographicOperations.ZeroMemory(blob);
        var folder = await GetFolderAsync().ConfigureAwait(true);
        var file = await folder.CreateFileAsync(RecoveryFileName, CreationCollisionOption.ReplaceExisting);
        await FileIO.WriteBytesAsync(file, payload);
        CryptographicOperations.ZeroMemory(payload);
        _recoveryCache = true;
        await RefreshKeyWrapsAsync().ConfigureAwait(true);
    }

    public async Task<(RecoveryVerifier Verifier, byte[] PlainBlob)> LoadRecoveryVerifierBundleAsync()
    {
        var folder = await GetFolderAsync().ConfigureAwait(true);
        var file = await folder.GetFileAsync(RecoveryFileName);
        await using var stream = await file.OpenStreamForReadAsync().ConfigureAwait(true);
        var wrapped = new byte[stream.Length];
        await stream.ReadExactlyAsync(wrapped).ConfigureAwait(true);
        byte[] inner;
        try
        {
            inner = UnwrapForThisUser(wrapped);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapped);
        }

        try
        {
            return (VaultRecovery.ParseVerifier(inner), inner);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(inner);
            throw;
        }
    }

    public bool RecoveryBindingIsValid(byte[] verifierBlob, VaultKey key)
    {
        ArgumentNullException.ThrowIfNull(verifierBlob);
        ArgumentNullException.ThrowIfNull(key);
        if (!_recoveryMacBound)
        {
            return true;
        }

        var keyBytes = key.CopyKeyBytes();
        try
        {
            return VaultRecovery.VerifyMac(verifierBlob, keyBytes, _recoveryMac);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    private async Task RefreshKeyWrapsAsync()
    {
        if (await HelloEnabledAsync().ConfigureAwait(true))
        {
            await WriteKeyWrapAsync(HelloFileName).ConfigureAwait(true);
        }

        if (await PanicWrapExistsAsync().ConfigureAwait(true))
        {
            await WriteKeyWrapAsync(PanicFileName).ConfigureAwait(true);
        }
    }

    public async Task<RecoveryVerifier> LoadRecoveryVerifierAsync()
    {
        var bundle = await LoadRecoveryVerifierBundleAsync().ConfigureAwait(true);
        try
        {
            return bundle.Verifier;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bundle.PlainBlob);
        }
    }

    public byte[] ProtectRecoveryWithHello(RecoveryMaterials materials)
    {
        ArgumentNullException.ThrowIfNull(materials);
        var plaintext = System.Text.Encoding.UTF8.GetBytes(materials.Key + "\n" + materials.Phrase);
        try
        {
            var protectedBytes = ProtectedData.Protect(plaintext, RecoveryHelloEntropy, DataProtectionScope.CurrentUser);
            var output = new byte[5 + protectedBytes.Length];
            RecoveryHelloMagic.CopyTo(output, 0);
            output[4] = 1;
            Buffer.BlockCopy(protectedBytes, 0, output, 5, protectedBytes.Length);
            CryptographicOperations.ZeroMemory(protectedBytes);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public static bool LooksLikeHelloRecoveryExport(byte[]? blob)
        => blob is { Length: >= 6 }
            && blob[0] == (byte)'S'
            && blob[1] == (byte)'R'
            && blob[2] == (byte)'H'
            && blob[3] == (byte)'1';

    public RecoveryMaterials OpenRecoveryWithHello(byte[] blob)
    {
        ArgumentNullException.ThrowIfNull(blob);
        if (!LooksLikeHelloRecoveryExport(blob) || blob[4] != 1)
        {
            throw new CryptographicException("That is not a Windows Hello recovery export.");
        }

        var protectedBytes = new byte[blob.Length - 5];
        Buffer.BlockCopy(blob, 5, protectedBytes, 0, protectedBytes.Length);
        try
        {
            var plaintext = ProtectedData.Unprotect(protectedBytes, RecoveryHelloEntropy, DataProtectionScope.CurrentUser);
            try
            {
                var text = System.Text.Encoding.UTF8.GetString(plaintext);
                var split = text.Split('\n', 2);
                if (split.Length != 2)
                {
                    throw new CryptographicException("That Windows Hello recovery export is damaged.");
                }

                return new RecoveryMaterials(split[0].Trim(), split[1].Trim());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("That recovery file is locked to another Windows user.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    public async Task ChangeMasterPasswordAsync(string newMasterPassword, bool clearHello = false)
    {
        EnsureUnlocked();
        VaultCryptography.EnsureMasterPassword(newMasterPassword);
        if (VaultCryptography.Matches(newMasterPassword, _sessionKey!))
        {
            throw new ArgumentException("The new master password must be different.", nameof(newMasterPassword));
        }

        var hello = await HelloEnabledAsync().ConfigureAwait(true);
        var panic = await PanicWrapExistsAsync().ConfigureAwait(true);
        var usb = await UsbUnlockEnabledAsync().ConfigureAwait(true);
        var newKey = await Task.Run(() => _crypto.CreateKey(newMasterPassword)).ConfigureAwait(true);
        var oldKey = _sessionKey;
        _sessionKey = newKey;
        InvalidateRecoveryMac();
        _document.Settings.MasterChangedUtc = DateTimeOffset.UtcNow;
        try
        {
            WrapExistingMediaKey();
            await PersistAsync().ConfigureAwait(true);
            await EnsureRecoveryMacAsync().ConfigureAwait(true);
            if (clearHello)
            {
                await DisableHelloAsync().ConfigureAwait(true);
            }
            else if (hello)
            {
                await WriteKeyWrapAsync(HelloFileName).ConfigureAwait(true);
            }

            if (panic)
            {
                await WriteKeyWrapAsync(PanicFileName).ConfigureAwait(true);
            }

            if (usb)
            {
                await DisableUsbUnlockAsync().ConfigureAwait(true);
            }
        }
        catch
        {
            _sessionKey = oldKey;
            newKey.Dispose();
            throw;
        }

        oldKey?.Dispose();
    }

    public async Task EnsureMasterRotationStampAsync(DateTimeOffset? nowUtc = null)
    {
        EnsureUnlocked();
        if (_document.Settings.MasterChangedUtc is { } stamped && stamped != default)
        {
            return;
        }

        _document.Settings.MasterChangedUtc = (nowUtc ?? DateTimeOffset.UtcNow).ToUniversalTime();
        await PersistAsync().ConfigureAwait(true);
    }

    public async Task<bool> PanicWrapExistsAsync()
    {
        var folder = await GetFolderAsync().ConfigureAwait(true);
        return (await folder.TryGetItemAsync(PanicFileName)) is not null;
    }

    public async Task<VaultKey> LoadPanicKeyAsync() => await LoadKeyWrapAsync(PanicFileName).ConfigureAwait(true);

    public async Task EnableUsbUnlockAsync(byte[] usbSecret)
    {
        EnsureUnlocked();
        if (_sessionKey is null)
        {
            throw new InvalidOperationException("The vault is locked.");
        }

        await EnsureRecoveryMacAsync().ConfigureAwait(true);
        var packed = PackSession(_sessionKey);
        try
        {
            var wrapped = UsbKeyCryptography.WrapPacked(packed, usbSecret);
            var folder = await GetFolderAsync().ConfigureAwait(true);
            var file = await folder.CreateFileAsync(UsbFileName, CreationCollisionOption.ReplaceExisting);
            await FileIO.WriteBytesAsync(file, wrapped);
            CryptographicOperations.ZeroMemory(wrapped);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(packed);
        }
    }

    public async Task<bool> UsbUnlockEnabledAsync()
    {
        var folder = await GetFolderAsync().ConfigureAwait(true);
        return (await folder.TryGetItemAsync(UsbFileName)) is not null;
    }

    public async Task DisableUsbUnlockAsync()
    {
        var folder = await GetFolderAsync().ConfigureAwait(true);
        if (await folder.TryGetItemAsync(UsbFileName) is StorageFile file)
        {
            await file.DeleteAsync();
        }
    }

    public async Task<VaultKey> LoadUsbUnlockAsync(byte[] usbSecret)
    {
        var folder = await GetFolderAsync().ConfigureAwait(true);
        var file = await folder.GetFileAsync(UsbFileName);
        await using var stream = await file.OpenStreamForReadAsync().ConfigureAwait(true);
        var wrapped = new byte[stream.Length];
        await stream.ReadExactlyAsync(wrapped).ConfigureAwait(true);
        try
        {
            var packed = UsbKeyCryptography.UnwrapPacked(wrapped, usbSecret);
            try
            {
                return UnpackSession(packed);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(packed);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapped);
        }
    }

    public void AddAttachment(VaultItem item, string fileName, byte[] data)
    {
        if (data.Length == 0 || data.Length > MaximumAttachmentBytes)
        {
            throw new InvalidOperationException("Attachments must be between 1 byte and 8 MB.");
        }

        item.Attachments.Add(new VaultAttachment
        {
            FileName = Path.GetFileName(fileName),
            ContentType = VaultItemRules.ContentTypeFor(fileName),
            Data = data.ToArray()
        });
    }

    public void Dispose()
    {
        Lock();
    }

    private async Task PersistAsync()
    {
        if (_sessionKey is null)
        {
            throw new InvalidOperationException("The vault is locked.");
        }

        var inner = await Task.Run(() => _crypto.Encrypt(_document, _sessionKey)).ConfigureAwait(true);
        var payload = WrapForThisUser(inner);
        CryptographicOperations.ZeroMemory(inner);

        var folder = await GetFolderAsync().ConfigureAwait(true);
        var temp = await folder.CreateFileAsync(TempFileName, CreationCollisionOption.ReplaceExisting);
        await FileIO.WriteBytesAsync(temp, payload);
        CryptographicOperations.ZeroMemory(payload);

        var destination = await folder.CreateFileAsync(FileName, CreationCollisionOption.OpenIfExists);
        await temp.MoveAndReplaceAsync(destination);
        _existsCache = true;
    }

    private async Task<byte[]> ReadInnerBlobAsync()
    {
        var folder = await GetFolderAsync().ConfigureAwait(true);
        var file = await folder.GetFileAsync(FileName);
        await using var stream = await file.OpenStreamForReadAsync().ConfigureAwait(true);
        if (stream.Length is 0 or > MaximumFileLength)
        {
            throw new CryptographicException("The vault file is damaged.");
        }

        var wrapped = new byte[stream.Length];
        await stream.ReadExactlyAsync(wrapped).ConfigureAwait(true);
        try
        {
            return UnwrapForThisUser(wrapped);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapped);
        }
    }

    private static byte[] WrapForThisUser(byte[] inner)
    {
        try
        {
            var protectedBytes = ProtectedData.Protect(inner, WrapEntropy, DataProtectionScope.CurrentUser);
            var output = new byte[5 + protectedBytes.Length];
            output[0] = (byte)'S';
            output[1] = (byte)'P';
            output[2] = (byte)'G';
            output[3] = (byte)'D';
            output[4] = 1;
            Buffer.BlockCopy(protectedBytes, 0, output, 5, protectedBytes.Length);
            CryptographicOperations.ZeroMemory(protectedBytes);
            return output;
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("Windows could not lock this vault to your user. The file was not saved in plaintext.");
        }
    }

    private static byte[] UnwrapForThisUser(byte[] blob)
    {
        if (blob.Length >= 5
            && blob[0] == (byte)'S'
            && blob[1] == (byte)'P'
            && blob[2] == (byte)'G'
            && blob[3] == (byte)'D')
        {
            var protectedBytes = new byte[blob.Length - 5];
            Buffer.BlockCopy(blob, 5, protectedBytes, 0, protectedBytes.Length);
            try
            {
                return ProtectedData.Unprotect(protectedBytes, WrapEntropy, DataProtectionScope.CurrentUser);
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("This vault is locked to another Windows user on this PC.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }

        var inner = new byte[blob.Length];
        Buffer.BlockCopy(blob, 0, inner, 0, blob.Length);
        return inner;
    }

    public async Task DeleteCurrentFilesAsync()
    {
        Lock();
        var folder = await GetFolderAsync().ConfigureAwait(true);
        foreach (var name in new[] { FileName, TempFileName, HelloFileName, PanicFileName, UsbFileName, RecoveryFileName, PendingAuditFileName })
        {
            if (await folder.TryGetItemAsync(name) is StorageFile file)
            {
                await OverwriteAndDeleteAsync(file).ConfigureAwait(true);
            }
        }

        if (await folder.TryGetItemAsync(MediaCryptography.BlobFolderName) is StorageFolder blobs)
        {
            await blobs.DeleteAsync(StorageDeleteOption.PermanentDelete);
        }

        if (!string.IsNullOrWhiteSpace(_folderName) && !ReferenceEquals(folder, ApplicationData.Current.LocalFolder))
        {
            try
            {
                await folder.DeleteAsync(StorageDeleteOption.PermanentDelete);
            }
            catch (Exception)
            {
            }
        }

        _cachedFolder = null;
        _existsCache = false;
        _helloCache = false;
        _recoveryCache = false;
    }

    private static async Task OverwriteAndDeleteAsync(StorageFile file)
    {
        try
        {
            await using var stream = await file.OpenStreamForWriteAsync().ConfigureAwait(true);
            var length = stream.Length;
            if (length > 0)
            {
                stream.Position = 0;
                var chunk = new byte[(int)Math.Min(length, 64 * 1024)];
                RandomNumberGenerator.Fill(chunk);
                var remaining = length;
                while (remaining > 0)
                {
                    var write = (int)Math.Min(remaining, chunk.Length);
                    await stream.WriteAsync(chunk.AsMemory(0, write)).ConfigureAwait(true);
                    remaining -= write;
                }

                await stream.FlushAsync().ConfigureAwait(true);
                CryptographicOperations.ZeroMemory(chunk);
            }
        }
        catch (Exception)
        {
        }

        await file.DeleteAsync();
    }

    private async Task<StorageFolder> GetFolderAsync()
    {
        if (_cachedFolder is not null)
        {
            return _cachedFolder;
        }

        var root = ApplicationData.Current.LocalFolder;
        if (string.IsNullOrWhiteSpace(_folderName) || !OccupantRules.IsSafeFolderName(_folderName))
        {
            _cachedFolder = root;
            return root;
        }

        var current = root;
        foreach (var part in _folderName.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (part is "." or "..")
            {
                continue;
            }

            current = await current.CreateFolderAsync(part, CreationCollisionOption.OpenIfExists);
        }

        _cachedFolder = current;
        return current;
    }

    private async Task<List<AuditEvent>> ReadPendingAuditAsync(StorageFolder folder)
    {
        if (await folder.TryGetItemAsync(PendingAuditFileName) is not StorageFile file)
        {
            return [];
        }

        await using var stream = await file.OpenStreamForReadAsync().ConfigureAwait(true);
        if (stream.Length is 0 or > MaximumPendingAuditLength)
        {
            return [];
        }

        var wrapped = new byte[stream.Length];
        await stream.ReadExactlyAsync(wrapped).ConfigureAwait(true);
        try
        {
            if (wrapped.Length < 5
                || wrapped[0] != (byte)'S'
                || wrapped[1] != (byte)'A'
                || wrapped[2] != (byte)'F'
                || wrapped[3] != (byte)'1')
            {
                return [];
            }

            var protectedBytes = new byte[wrapped.Length - 5];
            Buffer.BlockCopy(wrapped, 5, protectedBytes, 0, protectedBytes.Length);
            byte[] utf8;
            try
            {
                utf8 = ProtectedData.Unprotect(protectedBytes, AuditPendingEntropy, DataProtectionScope.CurrentUser);
            }
            catch (CryptographicException)
            {
                return [];
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }

            try
            {
                return AuditRules.FromUtf8(utf8);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(utf8);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapped);
        }
    }

    private async Task WritePendingAuditAsync(StorageFolder folder, List<AuditEvent> events)
    {
        var utf8 = AuditRules.ToUtf8(events);
        byte[] protectedBytes;
        try
        {
            protectedBytes = ProtectedData.Protect(utf8, AuditPendingEntropy, DataProtectionScope.CurrentUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
        }

        var output = new byte[5 + protectedBytes.Length];
        output[0] = (byte)'S';
        output[1] = (byte)'A';
        output[2] = (byte)'F';
        output[3] = (byte)'1';
        output[4] = 1;
        Buffer.BlockCopy(protectedBytes, 0, output, 5, protectedBytes.Length);
        CryptographicOperations.ZeroMemory(protectedBytes);

        var file = await folder.CreateFileAsync(PendingAuditFileName, CreationCollisionOption.ReplaceExisting);
        await FileIO.WriteBytesAsync(file, output);
        CryptographicOperations.ZeroMemory(output);
    }

    private static async Task DeletePendingAuditAsync(StorageFolder folder)
    {
        if (await folder.TryGetItemAsync(PendingAuditFileName) is StorageFile file)
        {
            await file.DeleteAsync();
        }
    }

    public MediaEntry? FindMedia(Guid id) => _document.Media.Find(entry => entry.Id == id);

    public async Task<MediaEntry> ImportMediaAsync(Stream plaintext, string fileName, string? category, long byteLength, string? organizerFolder = null)
    {
        EnsureUnlocked();
        ArgumentNullException.ThrowIfNull(plaintext);
        EnsureMediaKey();
        var id = Guid.NewGuid();
        var name = Path.GetFileName(fileName);
        var contentType = MediaCryptography.ContentTypeFor(name);
        var resolved = string.IsNullOrWhiteSpace(category)
            ? MediaCryptography.InferCategory(name, contentType)
            : category.Trim();
        var folder = await GetBlobFolderAsync().ConfigureAwait(true);
        var blob = await folder.CreateFileAsync(MediaCryptography.BlobFileName(id), CreationCollisionOption.ReplaceExisting);
        var fileKey = MediaCryptography.FileKey(_mediaKey!, id);
        try
        {
            await using var output = await blob.OpenStreamForWriteAsync().ConfigureAwait(true);
            await MediaCryptography.EncryptAsync(plaintext, output, fileKey, id).ConfigureAwait(true);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(fileKey);
            try
            {
                await blob.DeleteAsync();
            }
            catch (Exception)
            {
            }

            throw;
        }

        CryptographicOperations.ZeroMemory(fileKey);
        var entry = new MediaEntry
        {
            Id = id,
            Category = resolved,
            Title = Path.GetFileNameWithoutExtension(name),
            Folder = VaultOrganizer.Normalize(organizerFolder),
            OriginalName = name,
            ContentType = contentType,
            ByteLength = byteLength > 0 ? byteLength : (plaintext.CanSeek ? plaintext.Length : 0),
            CreatedUtc = DateTimeOffset.UtcNow,
            ModifiedUtc = DateTimeOffset.UtcNow
        };
        _document.Media.Insert(0, entry);
        try
        {
            await PersistAsync().ConfigureAwait(true);
        }
        catch
        {
            _document.Media.Remove(entry);
            try
            {
                await blob.DeleteAsync();
            }
            catch (Exception)
            {
            }

            throw;
        }

        return entry;
    }

    public async Task DecryptMediaAsync(Guid id, Stream destination)
    {
        EnsureUnlocked();
        ArgumentNullException.ThrowIfNull(destination);
        var entry = FindMedia(id) ?? throw new InvalidOperationException("That multimedia item is not in this vault.");
        EnsureMediaKey();
        var folder = await GetBlobFolderAsync().ConfigureAwait(true);
        var blob = await folder.TryGetItemAsync(MediaCryptography.BlobFileName(entry.Id));
        if (blob is not StorageFile file)
        {
            throw new InvalidOperationException("That multimedia blob is missing from disk.");
        }
        var fileKey = MediaCryptography.FileKey(_mediaKey!, entry.Id);
        try
        {
            await using var input = await file.OpenStreamForReadAsync().ConfigureAwait(true);
            await MediaCryptography.DecryptAsync(input, destination, fileKey, entry.Id).ConfigureAwait(true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    public async Task DeleteMediaAsync(Guid id)
    {
        EnsureUnlocked();
        var entry = FindMedia(id);
        if (entry is not null)
        {
            entry.Title = string.Empty;
            entry.OriginalName = string.Empty;
            _document.Media.Remove(entry);
        }

        var folder = await GetBlobFolderAsync().ConfigureAwait(true);
        if (await folder.TryGetItemAsync(MediaCryptography.BlobFileName(id)) is StorageFile file)
        {
            await file.DeleteAsync();
        }

        await PersistAsync().ConfigureAwait(true);
    }

    public void RenameMedia(Guid id, string title)
    {
        EnsureUnlocked();
        var entry = FindMedia(id) ?? throw new InvalidOperationException("That multimedia item is not in this vault.");
        entry.Title = string.IsNullOrWhiteSpace(title) ? entry.OriginalName : title.Trim();
        entry.ModifiedUtc = DateTimeOffset.UtcNow;
    }

    public void SetMediaFolder(Guid id, string folder)
    {
        EnsureUnlocked();
        var entry = FindMedia(id) ?? throw new InvalidOperationException("That multimedia item is not in this vault.");
        entry.Folder = VaultOrganizer.Normalize(folder);
        entry.ModifiedUtc = DateTimeOffset.UtcNow;
    }

    private void LoadMediaKey()
    {
        ClearMediaKey();
        var wrap = _document.Settings.MediaKeyWrap;
        if (wrap is not { Length: > 0 } || _sessionKey is null)
        {
            return;
        }

        var kek = _sessionKey.CopyKeyBytes();
        try
        {
            _mediaKey = MediaCryptography.UnwrapMasterKey(kek, wrap);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    private void EnsureMediaKey()
    {
        EnsureUnlocked();
        if (_mediaKey is { Length: MediaCryptography.KeySize })
        {
            return;
        }

        _mediaKey = MediaCryptography.CreateMasterKey();
        WrapExistingMediaKey();
    }

    private void WrapExistingMediaKey()
    {
        if (_mediaKey is null || _sessionKey is null)
        {
            return;
        }

        var kek = _sessionKey.CopyKeyBytes();
        try
        {
            if (_document.Settings.MediaKeyWrap is { Length: > 0 } previous)
            {
                CryptographicOperations.ZeroMemory(previous);
            }

            _document.Settings.MediaKeyWrap = MediaCryptography.WrapMasterKey(kek, _mediaKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    private void ClearMediaKey()
    {
        if (_mediaKey is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_mediaKey);
        _mediaKey = null;
    }

    private async Task<StorageFolder> GetBlobFolderAsync()
    {
        var folder = await GetFolderAsync().ConfigureAwait(true);
        return await folder.CreateFolderAsync(MediaCryptography.BlobFolderName, CreationCollisionOption.OpenIfExists);
    }

    private byte[] EnterPending(bool freshVault)
    {
        if (_pendingBind is not null)
        {
            CryptographicOperations.ZeroMemory(_pendingBind);
        }

        _pendingBind = RandomNumberGenerator.GetBytes(32);
        _pendingExpires = DateTimeOffset.UtcNow.AddMinutes(3);
        _pendingFreshVault = freshVault;
        _access = VaultAccessState.PendingHumanVerification;
        var copy = new byte[_pendingBind.Length];
        Buffer.BlockCopy(_pendingBind, 0, copy, 0, copy.Length);
        return copy;
    }

    private void DiscardPendingHold()
    {
        _pendingHold?.Dispose();
        _pendingHold = null;
    }

    private void DisposeSession()
    {
        _sessionKey?.Dispose();
        _sessionKey = null;
        ClearMediaKey();
    }

    private void EnsureUnlocked()
    {
        if (!IsUnlocked)
        {
            throw new InvalidOperationException("The vault is locked.");
        }
    }

    private static VaultItem CloneItem(VaultItem item)
    {
        return new VaultItem
        {
            Id = item.Id,
            Kind = item.Kind,
            Title = item.Title,
            Folder = item.Folder,
            Url = item.Url,
            BrowserContainer = item.BrowserContainer,
            Username = item.Username,
            Password = item.Password,
            PasswordHistory = CloneHistory(item.PasswordHistory),
            TotpSecret = item.TotpSecret,
            AliasEmail = item.AliasEmail,
            Mailbox = item.Mailbox,
            Cardholder = item.Cardholder,
            CardNumber = item.CardNumber,
            CardExpiry = item.CardExpiry,
            CardCvv = item.CardCvv,
            FullName = item.FullName,
            Phone = item.Phone,
            Address = item.Address,
            WifiSecurity = item.WifiSecurity,
            Notes = item.Notes,
            CreatedUtc = item.CreatedUtc,
            ModifiedUtc = item.ModifiedUtc,
            PasswordChangedUtc = item.PasswordChangedUtc,
            LastUsedUtc = item.LastUsedUtc,
            Attachments = item.Attachments.Select(file => new VaultAttachment
            {
                Id = file.Id,
                FileName = file.FileName,
                ContentType = file.ContentType,
                Data = file.Data.ToArray()
            }).ToList()
        };
    }

    private static List<PasswordHistoryEntry> CloneHistory(List<PasswordHistoryEntry>? history)
    {
        if (history is null || history.Count == 0)
        {
            return [];
        }

        var copy = new List<PasswordHistoryEntry>(history.Count);
        for (var i = 0; i < history.Count; i++)
        {
            var entry = history[i];
            copy.Add(new PasswordHistoryEntry
            {
                Password = entry.Password,
                ReplacedUtc = entry.ReplacedUtc
            });
        }

        return copy;
    }

    private void InvalidateRecoveryMac()
    {
        _recoveryMacBound = false;
        if (_recoveryMac is not null)
        {
            CryptographicOperations.ZeroMemory(_recoveryMac);
            _recoveryMac = null;
        }
    }

    private async Task EnsureRecoveryMacAsync()
    {
        if (_recoveryMacBound || _sessionKey is null || !await RecoveryConfiguredAsync().ConfigureAwait(true))
        {
            return;
        }

        var bundle = await LoadRecoveryVerifierBundleAsync().ConfigureAwait(true);
        var keyBytes = _sessionKey.CopyKeyBytes();
        try
        {
            _recoveryMac = VaultRecovery.MacVerifier(bundle.PlainBlob, keyBytes);
            _recoveryMacBound = true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
            CryptographicOperations.ZeroMemory(bundle.PlainBlob);
        }
    }

    private async Task WriteKeyWrapAsync(string fileName)
    {
        EnsureUnlocked();
        if (_sessionKey is null)
        {
            throw new InvalidOperationException("The vault is locked.");
        }

        await EnsureRecoveryMacAsync().ConfigureAwait(true);
        var packed = PackSession(_sessionKey);
        try
        {
            byte[] protectedBytes;
            if (PlatformKeyWrap.TryProtect(packed, out var hardware))
            {
                protectedBytes = hardware;
            }
            else
            {
                protectedBytes = ProtectedData.Protect(packed, WrapEntropy, DataProtectionScope.CurrentUser);
            }

            var folder = await GetFolderAsync().ConfigureAwait(true);
            var file = await folder.CreateFileAsync(fileName, CreationCollisionOption.ReplaceExisting);
            await FileIO.WriteBytesAsync(file, protectedBytes);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(packed);
        }
    }

    private async Task<VaultKey> LoadKeyWrapAsync(string fileName)
    {
        var folder = await GetFolderAsync().ConfigureAwait(true);
        var file = await folder.GetFileAsync(fileName);
        await using var stream = await file.OpenStreamForReadAsync().ConfigureAwait(true);
        var protectedBytes = new byte[stream.Length];
        await stream.ReadExactlyAsync(protectedBytes).ConfigureAwait(true);
        try
        {
            byte[] packed;
            if (PlatformWrapBlob.LooksLike(protectedBytes))
            {
                if (!PlatformKeyWrap.TryUnprotect(protectedBytes, out packed))
                {
                    throw new CryptographicException("Windows Hello hardware unlock failed.");
                }
            }
            else
            {
                packed = ProtectedData.Unprotect(protectedBytes, WrapEntropy, DataProtectionScope.CurrentUser);
            }

            try
            {
                return UnpackSession(packed);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(packed);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private byte[] PackSession(VaultKey key)
    {
        using var output = new MemoryStream();
        using var writer = new BinaryWriter(output);
        writer.Write((byte)2);
        writer.Write(key.MemoryKiB);
        writer.Write(key.Iterations);
        writer.Write((byte)key.Parallelism);
        writer.Write(key.Salt.Length);
        writer.Write(key.Salt);
        var keyBytes = key.CopyKeyBytes();
        writer.Write(keyBytes.Length);
        writer.Write(keyBytes);
        CryptographicOperations.ZeroMemory(keyBytes);
        var mac = _recoveryMac ?? new byte[32];
        writer.Write(mac.Length);
        writer.Write(mac);
        return output.ToArray();
    }

    private VaultKey UnpackSession(byte[] packed)
    {
        using var input = new MemoryStream(packed, writable: false);
        using var reader = new BinaryReader(input);
        var version = reader.ReadByte();
        if (version is not 1 and not 2)
        {
            throw new CryptographicException("Windows Hello unlock data is not valid.");
        }

        var memory = reader.ReadInt32();
        var iterations = reader.ReadInt32();
        var parallelism = reader.ReadByte();
        var salt = reader.ReadBytes(reader.ReadInt32());
        var keyBytes = reader.ReadBytes(reader.ReadInt32());
        _recoveryMacBound = false;
        if (_recoveryMac is not null)
        {
            CryptographicOperations.ZeroMemory(_recoveryMac);
            _recoveryMac = null;
        }

        if (version == 2 && input.Position < input.Length)
        {
            var mac = reader.ReadBytes(reader.ReadInt32());
            if (mac.Length == 32 && mac.Any(static value => value != 0))
            {
                _recoveryMac = mac;
                _recoveryMacBound = true;
            }
            else
            {
                CryptographicOperations.ZeroMemory(mac);
            }
        }

        return VaultKey.FromStored(keyBytes, salt, memory, iterations, parallelism);
    }
}

internal static class BufferExtensions
{
    public static byte[] ToArray(this Windows.Storage.Streams.IBuffer buffer)
    {
        var data = new byte[buffer.Length];
        Windows.Storage.Streams.DataReader.FromBuffer(buffer).ReadBytes(data);
        return data;
    }
}
