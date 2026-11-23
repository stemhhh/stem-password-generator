using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class UsbKeyCryptography
{
    public const string StickFileName = "stem-usb.key";
    public const string ReadmeFileName = "STEM-USB-KEY.txt";
    public const int SecretSize = 32;

    private const byte Version = 1;
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;
    private static readonly byte[] StickMagic = "SUK1"u8.ToArray();
    private static readonly byte[] WrapMagic = "SUKP"u8.ToArray();
    private static readonly byte[] StickAd = "STEM-USB-KEY"u8.ToArray();
    private static readonly byte[] WrapAd = "STEM-USB-WRAP"u8.ToArray();

    public static byte[] CreateSecret() => RandomNumberGenerator.GetBytes(SecretSize);

    public static byte[] CreateStickBlob(byte[] usbSecret, string pin)
    {
        ValidateSecret(usbSecret);
        VaultCryptography.EnsureMasterPassword(pin);
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var profile = Argon2Profile.Current;
        var key = Derive(pin, salt, profile);
        var ciphertext = new byte[usbSecret.Length];
        var tag = new byte[TagSize];
        try
        {
            using (var aes = new AesGcm(key, TagSize))
            {
                aes.Encrypt(nonce, usbSecret, ciphertext, tag, StickAd);
            }

            var blob = new byte[4 + 1 + 1 + 4 + 4 + 1 + SaltSize + NonceSize + TagSize + ciphertext.Length];
            StickMagic.CopyTo(blob, 0);
            blob[4] = Version;
            blob[5] = 1;
            BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(6), profile.MemoryKiB);
            BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(10), profile.Iterations);
            blob[14] = (byte)profile.Parallelism;
            salt.CopyTo(blob.AsSpan(15));
            nonce.CopyTo(blob.AsSpan(31));
            tag.CopyTo(blob.AsSpan(43));
            ciphertext.CopyTo(blob.AsSpan(59));
            return blob;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    public static byte[] OpenStickBlob(byte[] blob, string pin)
    {
        ArgumentNullException.ThrowIfNull(blob);
        VaultCryptography.EnsureMasterPassword(pin);
        if (blob.Length < 59 + SecretSize || !MagicEquals(blob, StickMagic) || blob[4] != Version || blob[5] != 1)
        {
            throw new CryptographicException("That is not a Stem USB key.");
        }

        var memory = BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(6));
        var iterations = BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(10));
        var parallelism = blob[14];
        var salt = blob.AsSpan(15, SaltSize).ToArray();
        var nonce = blob.AsSpan(31, NonceSize);
        var tag = blob.AsSpan(43, TagSize);
        var ciphertext = blob.AsSpan(59);
        if (ciphertext.Length != SecretSize)
        {
            throw new CryptographicException("That Stem USB key is damaged.");
        }

        var key = Derive(pin, salt, new Argon2Profile(memory, iterations, parallelism));
        var secret = new byte[SecretSize];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, secret, StickAd);
            return secret;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(secret);
            throw new CryptographicException("Wrong USB key PIN or the stick is damaged.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public static byte[] WrapPacked(byte[] packed, byte[] usbSecret)
    {
        ArgumentNullException.ThrowIfNull(packed);
        ValidateSecret(usbSecret);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var fingerprint = SHA256.HashData(usbSecret);
        var ciphertext = new byte[packed.Length];
        var tag = new byte[TagSize];
        try
        {
            using (var aes = new AesGcm(usbSecret, TagSize))
            {
                aes.Encrypt(nonce, packed, ciphertext, tag, WrapAd);
            }

            var blob = new byte[4 + 1 + fingerprint.Length + NonceSize + TagSize + ciphertext.Length];
            WrapMagic.CopyTo(blob, 0);
            blob[4] = Version;
            fingerprint.CopyTo(blob.AsSpan(5));
            nonce.CopyTo(blob.AsSpan(37));
            tag.CopyTo(blob.AsSpan(49));
            ciphertext.CopyTo(blob.AsSpan(65));
            return blob;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public static byte[] UnwrapPacked(byte[] blob, byte[] usbSecret)
    {
        ArgumentNullException.ThrowIfNull(blob);
        ValidateSecret(usbSecret);
        if (blob.Length < 66 || !MagicEquals(blob, WrapMagic) || blob[4] != Version)
        {
            throw new CryptographicException("USB unlock is not set up on this PC.");
        }

        var expected = SHA256.HashData(usbSecret);
        if (!CryptographicOperations.FixedTimeEquals(expected, blob.AsSpan(5, 32)))
        {
            throw new CryptographicException("That USB key is not registered to this vault.");
        }

        var nonce = blob.AsSpan(37, NonceSize);
        var tag = blob.AsSpan(49, TagSize);
        var ciphertext = blob.AsSpan(65);
        var packed = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(usbSecret, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, packed, WrapAd);
            return packed;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(packed);
            throw new CryptographicException("That USB key is not registered to this vault.");
        }
    }

    public static bool LooksLikeStick(byte[] blob) =>
        blob.Length >= 59 + SecretSize && MagicEquals(blob, StickMagic);

    public static string ReadmeText()
    {
        var en = """
            STEM USB ACCESS KEY
            -------------------
            AES-256-GCM + Argon2id. This flash drive is a physical key for Stem Password Generator on this Windows user.

            It is not a FIDO2 / YubiKey / Windows Hello security key. Chrome, Edge, and other apps will not treat this stick as a hardware login key.

            Keep the USB PIN separate from the stick. If you lose the stick, unlock Stem with the master password. If you forget the master password, Stem cannot recover the vault.

            To use the stick as a normal USB again, open Stem → USB key → Restore as normal storage, or format it in Windows Explorer (FAT32, exFAT, or NTFS).
            """;
        var es = """
            LLAVE USB DE ACCESO STEM
            ------------------------
            AES-256-GCM + Argon2id. Esta memoria es una llave física para Stem Password Generator en este usuario de Windows.

            No es una llave FIDO2 / YubiKey / Windows Hello. Chrome, Edge y otras apps no van a tratar este USB como una llave de hardware.

            Guarda el PIN del USB aparte del palo. Si pierdes el USB, desbloquea Stem con la contraseña maestra. Si olvidas la maestra, Stem no puede recuperar la bóveda.

            Para volver a usarlo como USB normal, abre Stem → Llave USB → Restaurar como almacenamiento normal, o formátalo en el Explorador de Windows (FAT32, exFAT o NTFS).
            """;
        return UiStrings.Language == AppLanguage.Spanish ? es : en;
    }

    private static byte[] Derive(string pin, byte[] salt, Argon2Profile profile)
    {
        var pinBytes = Encoding.UTF8.GetBytes(pin);
        try
        {
            using var argon2 = new Argon2id(pinBytes)
            {
                Salt = salt,
                DegreeOfParallelism = Math.Clamp(profile.Parallelism, 1, 8),
                Iterations = Math.Clamp(profile.Iterations, 1, 4),
                MemorySize = Math.Clamp(profile.MemoryKiB, Argon2Profile.MinimumMemoryKiB, Argon2Profile.MaximumMemoryKiB)
            };
            return argon2.GetBytes(KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pinBytes);
        }
    }

    private static void ValidateSecret(byte[] usbSecret)
    {
        ArgumentNullException.ThrowIfNull(usbSecret);
        if (usbSecret.Length != SecretSize)
        {
            throw new ArgumentException("USB secret must be 32 bytes.", nameof(usbSecret));
        }
    }

    private static bool MagicEquals(byte[] blob, byte[] magic) =>
        blob.Length >= 4 && blob[0] == magic[0] && blob[1] == magic[1] && blob[2] == magic[2] && blob[3] == magic[3];
}
