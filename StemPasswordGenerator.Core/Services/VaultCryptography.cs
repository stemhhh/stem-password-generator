using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Konscious.Security.Cryptography;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public sealed class VaultCryptography
{
    public const int MinimumMasterPasswordLength = 12;
    public const int CurrentVersion = 1;
    public const int MaximumBlobLength = 24 * 1024 * 1024;

    private const uint Magic = 0x31475053; // "SPG1" little-endian
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;
    private const int HeaderSize = 59;
    private const int MaxArgon2Iterations = 4;
    private const int MaxArgon2Parallelism = 8;

    private static readonly byte[] AssociatedDataLegacy = "SPG-VAULT"u8.ToArray();
    private const int AssociatedHeaderLength = 31; // magic through salt; nonce is the GCM nonce

    public byte[] Encrypt(VaultDocument document, string masterPassword)
    {
        using var key = CreateKey(masterPassword);
        return Encrypt(document, key);
    }

    public byte[] Encrypt(VaultDocument document, VaultKey key)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(key);

        var plaintext = JsonSerializer.SerializeToUtf8Bytes(document, VaultJsonContext.Default.VaultDocument);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var keyBytes = key.UseKey(static bytes => bytes.AsSpan(0, 32).ToArray());
        try
        {
            var blob = new byte[HeaderSize + plaintext.Length];
            BinaryPrimitives.WriteUInt32LittleEndian(blob, Magic);
            blob[4] = CurrentVersion;
            blob[5] = 1; // Argon2id
            BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(6), key.MemoryKiB);
            BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(10), key.Iterations);
            blob[14] = (byte)key.Parallelism;
            key.Salt.CopyTo(blob.AsSpan(15, SaltSize));
            nonce.CopyTo(blob.AsSpan(31, NonceSize));
            var tag = blob.AsSpan(43, TagSize);
            using (var aes = new AesGcm(keyBytes, TagSize))
            {
                aes.Encrypt(nonce, plaintext, blob.AsSpan(HeaderSize), tag, AssociatedData(blob));
            }

            return blob;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public VaultDocument Decrypt(byte[] blob, string masterPassword)
    {
        var document = Decrypt(blob, masterPassword, out var key);
        key.Dispose();
        return document;
    }

    public VaultDocument Decrypt(byte[] blob, string masterPassword, out VaultKey key)
    {
        ArgumentNullException.ThrowIfNull(blob);
        EnsureMasterPassword(masterPassword);
        key = null!;
        ValidateBlob(blob);

        try
        {
            using var input = new MemoryStream(blob, writable: false);
            using var reader = new BinaryReader(input);
            if (reader.ReadUInt32() != Magic)
            {
                throw new CryptographicException("This file is not a Stem vault.");
            }

            var version = reader.ReadByte();
            if (version != CurrentVersion)
            {
                throw new CryptographicException("This vault was created by a newer app version.");
            }

            var kdf = reader.ReadByte();
            if (kdf != 1)
            {
                throw new CryptographicException("Unsupported key derivation.");
            }

            var memoryKiB = reader.ReadInt32();
            var iterations = reader.ReadInt32();
            var parallelism = reader.ReadByte();
            var salt = reader.ReadBytes(SaltSize);
            var nonce = reader.ReadBytes(NonceSize);
            var tag = reader.ReadBytes(TagSize);
            if (salt.Length != SaltSize || nonce.Length != NonceSize || tag.Length != TagSize)
            {
                throw new CryptographicException("The vault file is damaged.");
            }

            var ciphertext = reader.ReadBytes((int)(input.Length - input.Position));
            var keyBytes = DeriveKey(masterPassword, salt, memoryKiB, iterations, parallelism);
            var plaintext = new byte[ciphertext.Length];
            try
            {
                DecryptGcm(keyBytes, nonce, ciphertext, tag, blob, plaintext);

                var document = Normalize(JsonSerializer.Deserialize(plaintext, VaultJsonContext.Default.VaultDocument) ?? new VaultDocument());
                key = new VaultKey(keyBytes, salt, ClampMemory(memoryKiB), ClampIterations(iterations), ClampParallelism(parallelism));
                keyBytes = null;
                return document;
            }
            catch (Exception exception) when (exception is CryptographicException or JsonException)
            {
                throw new CryptographicException("Wrong master password or the vault is damaged.");
            }
            finally
            {
                if (keyBytes is not null)
                {
                    CryptographicOperations.ZeroMemory(keyBytes);
                }

                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch (EndOfStreamException)
        {
            throw new CryptographicException("The vault file is damaged.");
        }
        catch (IOException)
        {
            throw new CryptographicException("The vault file is damaged.");
        }
    }

    public VaultKey CreateKey(string masterPassword)
    {
        EnsureMasterPassword(masterPassword);
        var profile = Argon2Profile.Current;
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var keyBytes = DeriveKey(masterPassword, salt, profile.MemoryKiB, profile.Iterations, profile.Parallelism);
        return new VaultKey(keyBytes, salt, profile.MemoryKiB, profile.Iterations, profile.Parallelism);
    }

    public VaultDocument Decrypt(byte[] blob, VaultKey key)
    {
        ArgumentNullException.ThrowIfNull(blob);
        ArgumentNullException.ThrowIfNull(key);
        ValidateBlob(blob);

        try
        {
            using var input = new MemoryStream(blob, writable: false);
            using var reader = new BinaryReader(input);
            if (reader.ReadUInt32() != Magic)
            {
                throw new CryptographicException("This file is not a Stem vault.");
            }

            var version = reader.ReadByte();
            if (version != CurrentVersion)
            {
                throw new CryptographicException("This vault was created by a newer app version.");
            }

            var kdf = reader.ReadByte();
            if (kdf != 1)
            {
                throw new CryptographicException("Unsupported key derivation.");
            }

            _ = reader.ReadInt32();
            _ = reader.ReadInt32();
            _ = reader.ReadByte();
            var salt = reader.ReadBytes(SaltSize);
            var nonce = reader.ReadBytes(NonceSize);
            var tag = reader.ReadBytes(TagSize);
            if (salt.Length != SaltSize || nonce.Length != NonceSize || tag.Length != TagSize)
            {
                throw new CryptographicException("The vault file is damaged.");
            }

            var ciphertext = reader.ReadBytes((int)(input.Length - input.Position));
            var plaintext = new byte[ciphertext.Length];
            var keyBytes = key.UseKey(static bytes => bytes.AsSpan(0, 32).ToArray());
            try
            {
                DecryptGcm(keyBytes, nonce, ciphertext, tag, blob, plaintext);

                return Normalize(JsonSerializer.Deserialize(plaintext, VaultJsonContext.Default.VaultDocument) ?? new VaultDocument());
            }
            catch (Exception exception) when (exception is CryptographicException or JsonException)
            {
                throw new CryptographicException("Wrong master password or the vault is damaged.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyBytes);
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch (EndOfStreamException)
        {
            throw new CryptographicException("The vault file is damaged.");
        }
        catch (IOException)
        {
            throw new CryptographicException("The vault file is damaged.");
        }
    }

    public static void EnsureMasterPassword(string masterPassword)
    {
        if (string.IsNullOrWhiteSpace(masterPassword) || masterPassword.Length < MinimumMasterPasswordLength)
        {
            throw new ArgumentException(
                $"The master password must be at least {MinimumMasterPasswordLength} characters.",
                nameof(masterPassword));
        }

        if (masterPassword.Distinct().Count() < 4)
        {
            throw new ArgumentException("The master password is too repetitive.", nameof(masterPassword));
        }
    }

    public static bool Matches(string masterPassword, VaultKey session)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (session.IsDisposed)
        {
            return false;
        }

        try
        {
            EnsureMasterPassword(masterPassword);
        }
        catch (ArgumentException)
        {
            return false;
        }

        var derived = DeriveKey(masterPassword, session.Salt, session.MemoryKiB, session.Iterations, session.Parallelism);
        try
        {
            return session.UseKey(sessionKey =>
                derived.Length == 32
                && CryptographicOperations.FixedTimeEquals(derived, sessionKey.AsSpan(0, 32)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derived);
        }
    }

    public static bool FixedEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left ?? string.Empty);
        var rightBytes = Encoding.UTF8.GetBytes(right ?? string.Empty);
        try
        {
            if (leftBytes.Length != rightBytes.Length)
            {
                CryptographicOperations.FixedTimeEquals(leftBytes, leftBytes);
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    public static void ClearDocument(VaultDocument document)
    {
        foreach (var item in document.Items)
        {
            item.Title = string.Empty;
            item.Url = string.Empty;
            item.BrowserContainer = string.Empty;
            item.Username = string.Empty;
            item.Password = string.Empty;
            if (item.PasswordHistory is not null)
            {
                for (var i = 0; i < item.PasswordHistory.Count; i++)
                {
                    item.PasswordHistory[i].Password = string.Empty;
                }

                item.PasswordHistory.Clear();
            }

            item.Notes = string.Empty;
            item.TotpSecret = string.Empty;
            item.AliasEmail = string.Empty;
            item.Mailbox = string.Empty;
            item.CardNumber = string.Empty;
            item.CardCvv = string.Empty;
            item.Phone = string.Empty;
            item.Address = string.Empty;
            item.WifiSecurity = string.Empty;
            foreach (var attachment in item.Attachments)
            {
                if (attachment.Data.Length > 0)
                {
                    CryptographicOperations.ZeroMemory(attachment.Data);
                }

                attachment.Data = [];
                attachment.FileName = string.Empty;
            }

            item.Attachments.Clear();
        }

        document.Items.Clear();
        document.Media ??= [];
        foreach (var media in document.Media)
        {
            media.Title = string.Empty;
            media.OriginalName = string.Empty;
            media.ContentType = string.Empty;
        }

        document.Media.Clear();
        document.Audit ??= [];
        foreach (var entry in document.Audit)
        {
            entry.Title = string.Empty;
            entry.Method = string.Empty;
            entry.Kind = string.Empty;
            entry.ItemKind = string.Empty;
            entry.ItemId = null;
        }

        document.Audit.Clear();
        if (document.Settings is not null)
        {
            document.Settings.PrimaryEmail = string.Empty;
            document.Settings.AliasDomain = string.Empty;
            document.Settings.Profiles ??= [];
            document.Settings.Mailboxes ??= [];
            if (document.Settings.MediaKeyWrap is { Length: > 0 } wrap)
            {
                CryptographicOperations.ZeroMemory(wrap);
            }

            document.Settings.MediaKeyWrap = null;
            foreach (var profile in document.Settings.Profiles)
            {
                profile.Email = string.Empty;
                profile.Label = string.Empty;
            }

            document.Settings.Profiles.Clear();
            document.Settings.Mailboxes.Clear();
        }

        document.Settings = new VaultSettings();
    }

    private static VaultDocument Normalize(VaultDocument document)
    {
        document.Settings ??= new VaultSettings();
        document.Items ??= [];
        document.Media ??= [];
        document.Audit ??= [];
        document.Settings.Mailboxes ??= [];
        document.Settings.Profiles ??= [];
        MailboxProfileService.Migrate(document.Settings);
        foreach (var item in document.Items)
        {
            item.Kind = string.IsNullOrWhiteSpace(item.Kind) ? VaultItemKind.Login : item.Kind;
            item.Attachments ??= [];
        }

        return document;
    }

    private static void DecryptGcm(byte[] keyBytes, byte[] nonce, byte[] ciphertext, byte[] tag, byte[] blob, byte[] plaintext)
    {
        try
        {
            using var aes = new AesGcm(keyBytes, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, AssociatedData(blob));
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            using var aes = new AesGcm(keyBytes, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, AssociatedDataLegacy);
        }
    }

    private static byte[] AssociatedData(byte[] blob)
    {
        var aad = new byte[AssociatedDataLegacy.Length + AssociatedHeaderLength];
        AssociatedDataLegacy.CopyTo(aad, 0);
        Buffer.BlockCopy(blob, 0, aad, AssociatedDataLegacy.Length, AssociatedHeaderLength);
        return aad;
    }

    private static void ValidateBlob(byte[] blob)
    {
        if (blob.Length < HeaderSize || blob.Length > MaximumBlobLength)
        {
            throw new CryptographicException("The vault file is damaged.");
        }
    }

    public static bool LooksLikeInner(byte[]? blob) =>
        blob is { Length: >= HeaderSize and <= MaximumBlobLength }
        && BinaryPrimitives.ReadUInt32LittleEndian(blob) == Magic
        && blob[4] == CurrentVersion;

    private static byte[] DeriveKey(
        string masterPassword,
        byte[] salt,
        int memoryKiB,
        int iterations,
        int parallelism)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(masterPassword);
        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = ClampParallelism(parallelism),
                Iterations = ClampIterations(iterations),
                MemorySize = ClampMemory(memoryKiB)
            };
            return argon2.GetBytes(KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static int ClampMemory(int memoryKiB) => Math.Clamp(memoryKiB, Argon2Profile.MinimumMemoryKiB, Argon2Profile.MaximumMemoryKiB);

    private static int ClampIterations(int iterations) => Math.Clamp(iterations, 1, MaxArgon2Iterations);

    private static int ClampParallelism(int parallelism) => Math.Clamp(parallelism, 1, MaxArgon2Parallelism);
}
