using System.Buffers.Binary;
using System.Security.Cryptography;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class MediaCryptography
{
    public const int KeySize = 32;
    public const int ChunkSize = 1024 * 1024;
    public const long MaximumFileBytes = 512L * 1024 * 1024;
    public const string BlobFolderName = "blk";
    public const string BlobExtension = ".spgm";

    private const byte Version = 1;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private static readonly byte[] FileMagic = "SPGM"u8.ToArray();
    private static readonly byte[] WrapMagic = "SMK1"u8.ToArray();
    private static readonly byte[] WrapAd = "STEM-MEDIA-KEK"u8.ToArray();
    private static readonly byte[] FileInfo = "STEM-MEDIA-FILE-v1"u8.ToArray();
    private static readonly byte[] ChunkAdPrefix = "STEM-MEDIA-CHUNK"u8.ToArray();

    public static byte[] CreateMasterKey() => RandomNumberGenerator.GetBytes(KeySize);

    public static byte[] WrapMasterKey(byte[] kek, byte[] mediaMasterKey)
    {
        ValidateKey(kek, nameof(kek));
        ValidateKey(mediaMasterKey, nameof(mediaMasterKey));
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[KeySize];
        var tag = new byte[TagSize];
        try
        {
            using (var aes = new AesGcm(kek, TagSize))
            {
                aes.Encrypt(nonce, mediaMasterKey, ciphertext, tag, WrapAd);
            }

            var blob = new byte[4 + 1 + NonceSize + TagSize + KeySize];
            WrapMagic.CopyTo(blob, 0);
            blob[4] = Version;
            nonce.CopyTo(blob.AsSpan(5));
            tag.CopyTo(blob.AsSpan(17));
            ciphertext.CopyTo(blob.AsSpan(33));
            return blob;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    public static byte[] UnwrapMasterKey(byte[] kek, byte[] wrap)
    {
        ValidateKey(kek, nameof(kek));
        ArgumentNullException.ThrowIfNull(wrap);
        if (wrap.Length != 4 + 1 + NonceSize + TagSize + KeySize
            || !wrap.AsSpan(0, 4).SequenceEqual(WrapMagic)
            || wrap[4] != Version)
        {
            throw new CryptographicException("The multimedia vault key wrap is damaged.");
        }

        var nonce = wrap.AsSpan(5, NonceSize);
        var tag = wrap.AsSpan(17, TagSize);
        var ciphertext = wrap.AsSpan(33, KeySize);
        var key = new byte[KeySize];
        try
        {
            using var aes = new AesGcm(kek, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, key, WrapAd);
            return key;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new CryptographicException("The multimedia vault key wrap is damaged.");
        }
    }

    public static byte[] FileKey(byte[] mediaMasterKey, Guid fileId)
    {
        ValidateKey(mediaMasterKey, nameof(mediaMasterKey));
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, mediaMasterKey, KeySize, fileId.ToByteArray(), FileInfo);
    }

    public static string BlobFileName(Guid id) => id.ToString("N") + BlobExtension;

    public static bool LooksLikeBlob(byte[] header) =>
        header.Length >= 4 && header.AsSpan(0, 4).SequenceEqual(FileMagic);

    public static async Task EncryptAsync(
        Stream plaintext,
        Stream ciphertext,
        byte[] fileKey,
        Guid fileId,
        int chunkSize = ChunkSize,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(ciphertext);
        ValidateKey(fileKey, nameof(fileKey));
        if (chunkSize is < 1024 or > ChunkSize)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkSize));
        }

        var header = new byte[21];
        FileMagic.CopyTo(header, 0);
        header[4] = Version;
        fileId.ToByteArray().CopyTo(header, 5);
        await ciphertext.WriteAsync(header, cancellationToken).ConfigureAwait(false);

        var buffer = new byte[chunkSize];
        var chunkIndex = 0;
        long total = 0;
        while (true)
        {
            var read = await plaintext.ReadAsync(buffer.AsMemory(0, chunkSize), cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                break;
            }

            total += read;
            if (total > MaximumFileBytes)
            {
                throw new InvalidOperationException($"Multimedia files must be at most {MaximumFileBytes / (1024 * 1024)} MB.");
            }

            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var cipher = new byte[read];
            var tag = new byte[TagSize];
            var aad = ChunkAad(fileId, chunkIndex);
            try
            {
                using (var aes = new AesGcm(fileKey, TagSize))
                {
                    aes.Encrypt(nonce, buffer.AsSpan(0, read), cipher, tag, aad);
                }

                var prefix = new byte[NonceSize + TagSize + 4];
                nonce.CopyTo(prefix.AsSpan(0));
                tag.CopyTo(prefix.AsSpan(NonceSize));
                BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(NonceSize + TagSize), read);
                await ciphertext.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
                await ciphertext.WriteAsync(cipher, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nonce);
                CryptographicOperations.ZeroMemory(cipher);
                CryptographicOperations.ZeroMemory(tag);
                CryptographicOperations.ZeroMemory(aad);
            }

            chunkIndex++;
        }

        CryptographicOperations.ZeroMemory(buffer);
        if (total == 0)
        {
            throw new InvalidOperationException("That file is empty.");
        }
    }

    public static async Task DecryptAsync(
        Stream ciphertext,
        Stream plaintext,
        byte[] fileKey,
        Guid expectedId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(plaintext);
        ValidateKey(fileKey, nameof(fileKey));

        var header = new byte[21];
        await ciphertext.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        if (!LooksLikeBlob(header) || header[4] != Version)
        {
            throw new CryptographicException("That is not a Stem multimedia blob.");
        }

        var fileId = new Guid(header.AsSpan(5, 16));
        if (fileId != expectedId)
        {
            throw new CryptographicException("That multimedia blob does not match this vault item.");
        }

        var chunkIndex = 0;
        var prefix = new byte[NonceSize + TagSize + 4];
        while (true)
        {
            var got = await ciphertext.ReadAtLeastAsync(prefix, prefix.Length, throwOnEndOfStream: false, cancellationToken)
                .ConfigureAwait(false);
            if (got == 0)
            {
                break;
            }

            if (got < prefix.Length)
            {
                throw new CryptographicException("That multimedia blob is damaged.");
            }

            var length = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(NonceSize + TagSize));
            if (length is < 1 or > ChunkSize)
            {
                throw new CryptographicException("That multimedia blob is damaged.");
            }

            var cipher = new byte[length];
            await ciphertext.ReadExactlyAsync(cipher, cancellationToken).ConfigureAwait(false);
            var plain = new byte[length];
            var aad = ChunkAad(fileId, chunkIndex);
            try
            {
                using var aes = new AesGcm(fileKey, TagSize);
                aes.Decrypt(prefix.AsSpan(0, NonceSize), cipher, prefix.AsSpan(NonceSize, TagSize), plain, aad);
                await plaintext.WriteAsync(plain, cancellationToken).ConfigureAwait(false);
            }
            catch (CryptographicException)
            {
                CryptographicOperations.ZeroMemory(plain);
                throw new CryptographicException("That multimedia blob is damaged or the vault is locked.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(cipher);
                CryptographicOperations.ZeroMemory(plain);
                CryptographicOperations.ZeroMemory(aad);
            }

            chunkIndex++;
        }

        if (chunkIndex == 0)
        {
            throw new CryptographicException("That multimedia blob is damaged.");
        }
    }

    public static string InferCategory(string fileName, string contentType)
    {
        var type = (contentType ?? string.Empty).ToLowerInvariant();
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        if (type.StartsWith("image/", StringComparison.Ordinal) || ext is ".png" or ".jpg" or ".jpeg" or ".webp" or ".gif" or ".heic" or ".bmp")
        {
            return MediaCategory.Photo;
        }

        if (type.StartsWith("video/", StringComparison.Ordinal) || ext is ".mp4" or ".mov" or ".webm" or ".mkv" or ".avi")
        {
            return MediaCategory.Video;
        }

        if (type.StartsWith("audio/", StringComparison.Ordinal) || ext is ".mp3" or ".wav" or ".m4a" or ".flac" or ".ogg" or ".aac")
        {
            return MediaCategory.Audio;
        }

        return MediaCategory.File;
    }

    public static string ContentTypeFor(string fileName)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        return ext switch
        {
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".webp" => "image/webp",
            ".gif" => "image/gif",
            ".heic" => "image/heic",
            ".bmp" => "image/bmp",
            ".mp4" => "video/mp4",
            ".mov" => "video/quicktime",
            ".webm" => "video/webm",
            ".mkv" => "video/x-matroska",
            ".mp3" => "audio/mpeg",
            ".wav" => "audio/wav",
            ".m4a" => "audio/mp4",
            ".flac" => "audio/flac",
            ".pdf" => "application/pdf",
            _ => VaultItemRules.ContentTypeFor(fileName)
        };
    }

    private static byte[] ChunkAad(Guid fileId, int chunkIndex)
    {
        var aad = new byte[ChunkAdPrefix.Length + 16 + 4];
        ChunkAdPrefix.CopyTo(aad, 0);
        fileId.ToByteArray().CopyTo(aad, ChunkAdPrefix.Length);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(ChunkAdPrefix.Length + 16), chunkIndex);
        return aad;
    }

    private static void ValidateKey(byte[] key, string name)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != KeySize)
        {
            throw new ArgumentException("Media keys must be 32 bytes.", name);
        }
    }
}
