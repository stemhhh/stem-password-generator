using System.Buffers.Binary;
using System.Security.Cryptography;

namespace StemPasswordGenerator.Services;

public static class PlatformWrapBlob
{
    public const uint Magic = 0x48545053; // "SPTH"
    public const byte Version = 1;
    public const int HeaderSize = 9;

    public static bool LooksLike(byte[]? blob) =>
        blob is { Length: > HeaderSize }
        && BinaryPrimitives.ReadUInt32LittleEndian(blob) == Magic
        && blob[4] == Version;

    public static byte[] Pack(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (ciphertext.Length is 0 or > 64 * 1024)
        {
            throw new CryptographicException("The wrapped key is not valid.");
        }

        var blob = new byte[HeaderSize + ciphertext.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(blob, Magic);
        blob[4] = Version;
        BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(5), ciphertext.Length);
        ciphertext.CopyTo(blob.AsSpan(HeaderSize));
        return blob;
    }

    public static byte[] Unpack(byte[] blob)
    {
        ArgumentNullException.ThrowIfNull(blob);
        if (!LooksLike(blob))
        {
            throw new CryptographicException("That is not a hardware-wrapped unlock file.");
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(5));
        if (length <= 0 || HeaderSize + length != blob.Length)
        {
            throw new CryptographicException("The hardware-wrapped unlock file is damaged.");
        }

        var ciphertext = new byte[length];
        Buffer.BlockCopy(blob, HeaderSize, ciphertext, 0, length);
        return ciphertext;
    }
}
