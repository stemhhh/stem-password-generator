using System.Buffers.Binary;
using System.Security.Cryptography;

namespace StemPasswordGenerator.Services;

internal static class KeePassStreamCipher
{
    private static readonly byte[] SalsaNonce = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];

    public static byte[] Salsa20(byte[] key, byte[] data) => Salsa20(key, SalsaNonce, data);

    public static byte[] Salsa20(byte[] key, byte[] nonce, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(nonce);
        ArgumentNullException.ThrowIfNull(data);
        if (key.Length != 32 || nonce.Length != 8)
        {
            throw new CryptographicException("The KeePass inner stream key is damaged.");
        }

        return Xor(data, Salsa20Keystream(key, nonce, data.Length));
    }

    public static byte[] ChaCha20(byte[] key, byte[] nonce, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(nonce);
        ArgumentNullException.ThrowIfNull(data);
        if (key.Length != 32 || nonce.Length != 12)
        {
            throw new CryptographicException("The KeePass inner stream key is damaged.");
        }

        return Xor(data, ChaCha20Keystream(key, nonce, data.Length));
    }

    public static byte[] InnerChaCha20(byte[] streamKey, byte[] data)
    {
        var hash = SHA512.HashData(streamKey);
        try
        {
            var key = hash.AsSpan(0, 32).ToArray();
            var nonce = hash.AsSpan(32, 12).ToArray();
            try
            {
                return ChaCha20(key, nonce, data);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(nonce);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static byte[] Xor(byte[] data, byte[] stream)
    {
        var output = new byte[data.Length];
        for (var i = 0; i < data.Length; i++)
        {
            output[i] = (byte)(data[i] ^ stream[i]);
        }

        CryptographicOperations.ZeroMemory(stream);
        return output;
    }

    private static byte[] ChaCha20Keystream(byte[] key, byte[] nonce, int length)
    {
        var output = new byte[length];
        var state = new uint[16];
        state[0] = 0x61707865;
        state[1] = 0x3320646E;
        state[2] = 0x79622D32;
        state[3] = 0x6B206574;
        for (var i = 0; i < 8; i++)
        {
            state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(i * 4));
        }

        state[12] = 0;
        for (var i = 0; i < 3; i++)
        {
            state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(i * 4));
        }

        var offset = 0;
        var block = new byte[64];
        var working = new uint[16];
        while (offset < length)
        {
            Array.Copy(state, working, 16);
            for (var i = 0; i < 10; i++)
            {
                Quarter(ref working[0], ref working[4], ref working[8], ref working[12]);
                Quarter(ref working[1], ref working[5], ref working[9], ref working[13]);
                Quarter(ref working[2], ref working[6], ref working[10], ref working[14]);
                Quarter(ref working[3], ref working[7], ref working[11], ref working[15]);
                Quarter(ref working[0], ref working[5], ref working[10], ref working[15]);
                Quarter(ref working[1], ref working[6], ref working[11], ref working[12]);
                Quarter(ref working[2], ref working[7], ref working[8], ref working[13]);
                Quarter(ref working[3], ref working[4], ref working[9], ref working[14]);
            }

            for (var i = 0; i < 16; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(i * 4), working[i] + state[i]);
            }

            var take = Math.Min(64, length - offset);
            Buffer.BlockCopy(block, 0, output, offset, take);
            offset += take;
            state[12]++;
        }

        CryptographicOperations.ZeroMemory(block);
        return output;
    }

    private static byte[] Salsa20Keystream(byte[] key, byte[] nonce, int length)
    {
        var output = new byte[length];
        var state = new uint[16];
        state[0] = 0x61707865;
        state[5] = 0x3320646E;
        state[10] = 0x79622D32;
        state[15] = 0x6B206574;
        for (var i = 0; i < 4; i++)
        {
            state[1 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(i * 4));
            state[11 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(16 + i * 4));
        }

        state[6] = BinaryPrimitives.ReadUInt32LittleEndian(nonce);
        state[7] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(4));
        state[8] = 0;
        state[9] = 0;

        var offset = 0;
        var block = new byte[64];
        var working = new uint[16];
        while (offset < length)
        {
            Array.Copy(state, working, 16);
            for (var i = 0; i < 10; i++)
            {
                SalsaQuarter(ref working[0], ref working[4], ref working[8], ref working[12]);
                SalsaQuarter(ref working[5], ref working[9], ref working[13], ref working[1]);
                SalsaQuarter(ref working[10], ref working[14], ref working[2], ref working[6]);
                SalsaQuarter(ref working[15], ref working[3], ref working[7], ref working[11]);
                SalsaQuarter(ref working[0], ref working[1], ref working[2], ref working[3]);
                SalsaQuarter(ref working[5], ref working[6], ref working[7], ref working[4]);
                SalsaQuarter(ref working[10], ref working[11], ref working[8], ref working[9]);
                SalsaQuarter(ref working[15], ref working[12], ref working[13], ref working[14]);
            }

            for (var i = 0; i < 16; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(i * 4), working[i] + state[i]);
            }

            var take = Math.Min(64, length - offset);
            Buffer.BlockCopy(block, 0, output, offset, take);
            offset += take;
            if (++state[8] == 0)
            {
                state[9]++;
            }
        }

        CryptographicOperations.ZeroMemory(block);
        return output;
    }

    private static void Quarter(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b;
        d = Rotate(d ^ a, 16);
        c += d;
        b = Rotate(b ^ c, 12);
        a += b;
        d = Rotate(d ^ a, 8);
        c += d;
        b = Rotate(b ^ c, 7);
    }

    private static void SalsaQuarter(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        b ^= Rotate(a + d, 7);
        c ^= Rotate(b + a, 9);
        d ^= Rotate(c + b, 13);
        a ^= Rotate(d + c, 18);
    }

    private static uint Rotate(uint value, int bits) => (value << bits) | (value >> (32 - bits));
}
