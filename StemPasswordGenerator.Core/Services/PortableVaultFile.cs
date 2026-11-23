using System.Buffers.Binary;
using System.Security.Cryptography;

namespace StemPasswordGenerator.Services;

public static class PortableVaultFile
{
    public const uint Magic = 0x50475053; // "SPGP" little-endian
    public const byte Version = 1;
    public const int HeaderSize = 10;

    public static bool LooksLikeDpapi(byte[]? blob) =>
        blob is { Length: >= 5 }
        && blob[0] == (byte)'S'
        && blob[1] == (byte)'P'
        && blob[2] == (byte)'G'
        && blob[3] == (byte)'D';

    public static bool LooksLike(byte[]? blob) =>
        blob is { Length: > HeaderSize }
        && BinaryPrimitives.ReadUInt32LittleEndian(blob) == Magic
        && blob[4] == Version;

    public static byte[] Pack(byte[] inner)
    {
        ArgumentNullException.ThrowIfNull(inner);
        if (!VaultCryptography.LooksLikeInner(inner))
        {
            throw new CryptographicException("That is not a Stem vault ciphertext.");
        }

        var packed = new byte[HeaderSize + inner.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(packed, Magic);
        packed[4] = Version;
        packed[5] = 0;
        BinaryPrimitives.WriteInt32LittleEndian(packed.AsSpan(6), inner.Length);
        Buffer.BlockCopy(inner, 0, packed, HeaderSize, inner.Length);
        return packed;
    }

    public static bool TryReadInner(byte[] blob, out byte[] inner)
    {
        inner = [];
        if (blob is null || LooksLikeDpapi(blob))
        {
            return false;
        }

        if (LooksLike(blob))
        {
            var length = BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(6));
            if (length <= 0 || HeaderSize + length != blob.Length)
            {
                return false;
            }

            inner = new byte[length];
            Buffer.BlockCopy(blob, HeaderSize, inner, 0, length);
            if (!VaultCryptography.LooksLikeInner(inner))
            {
                CryptographicOperations.ZeroMemory(inner);
                inner = [];
                return false;
            }

            return true;
        }

        if (!VaultCryptography.LooksLikeInner(blob))
        {
            return false;
        }

        inner = new byte[blob.Length];
        Buffer.BlockCopy(blob, 0, inner, 0, blob.Length);
        return true;
    }
}
