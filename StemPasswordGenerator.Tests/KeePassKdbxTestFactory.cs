using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using StemPasswordGenerator.Services;

namespace StemPasswordGenerator.Tests;

internal static class KeePassKdbxTestFactory
{
    private static readonly byte[] Aes256 = Convert.FromHexString("31C1F2E6BF714350BE5805216AFC5AFF");
    private static readonly byte[] AesKdf = Convert.FromHexString("C9D9F39A628A4460BF740D08C18A4FEA");
    private static readonly byte[] Argon2id = Convert.FromHexString("9E298B1956DB4773B23DFC3EC6F0A1E6");

    public static byte[] WriteV3(string password, SampleEntry entry, bool protectPassword = false)
    {
        var masterSeed = RandomBytes(32);
        var transformSeed = RandomBytes(32);
        var iv = RandomBytes(16);
        var streamKey = RandomBytes(32);
        var streamStart = RandomBytes(32);
        const ulong rounds = 12;

        var xml = Encoding.UTF8.GetBytes(Xml(entry, protectPassword, streamId: 2, streamKey));
        var hashed = HashedBlocks(xml);
        var plain = Concat(streamStart, hashed);
        var transformed = AesKdfTransform(Composite(password), transformSeed, rounds);
        var cipherKey = SHA256.HashData(Concat(masterSeed, transformed));
        var encrypted = AesCbcEncrypt(cipherKey, iv, plain);

        using var output = new MemoryStream();
        WriteSignature(output, major: 3, minor: 1);
        WriteField16(output, 2, Aes256);
        WriteField16(output, 3, UInt32Bytes(0));
        WriteField16(output, 4, masterSeed);
        WriteField16(output, 5, transformSeed);
        WriteField16(output, 6, UInt64Bytes(rounds));
        WriteField16(output, 7, iv);
        WriteField16(output, 8, streamKey);
        WriteField16(output, 9, streamStart);
        WriteField16(output, 10, UInt32Bytes(2));
        WriteField16(output, 0, [0x0D, 0x0A, 0x0D, 0x0A]);
        output.Write(encrypted);
        return output.ToArray();
    }

    public static byte[] WriteV4(string password, SampleEntry entry, bool argon2)
    {
        var masterSeed = RandomBytes(32);
        var iv = RandomBytes(16);
        var streamKey = RandomBytes(64);
        var kdfSeed = RandomBytes(32);
        const ulong rounds = 8;
        const ulong argonMemory = 8UL * 1024 * 1024;
        const uint argonIterations = 1;

        var inner = Concat(InnerHeader(streamKey), Encoding.UTF8.GetBytes(Xml(entry, protectPassword: false, streamId: 3, streamKey)));
        var transformed = argon2
            ? Argon2idTransform(Composite(password), kdfSeed, argonMemory, argonIterations, parallelism: 1)
            : AesKdfTransform(Composite(password), kdfSeed, rounds);
        var cipherKey = SHA256.HashData(Concat(masterSeed, transformed));
        var hmacKey = SHA512.HashData(Concat(masterSeed, transformed, [1]));
        var encrypted = AesCbcEncrypt(cipherKey, iv, inner);

        using var header = new MemoryStream();
        WriteSignature(header, major: 4, minor: 0);
        WriteField32(header, 2, Aes256);
        WriteField32(header, 3, UInt32Bytes(0));
        WriteField32(header, 4, masterSeed);
        WriteField32(header, 7, iv);
        WriteField32(header, 11, argon2
            ? Argon2Parameters(kdfSeed, argonMemory, argonIterations, 1)
            : AesKdfParameters(kdfSeed, rounds));
        WriteField32(header, 0, [0x0D, 0x0A, 0x0D, 0x0A]);
        var headerBytes = header.ToArray();

        using var output = new MemoryStream();
        output.Write(headerBytes);
        output.Write(SHA256.HashData(headerBytes));
        var headerHmacKey = BlockKey(hmacKey, ulong.MaxValue);
        output.Write(Hmac(headerHmacKey, headerBytes));
        WriteHmacBlock(output, hmacKey, 0, encrypted);
        WriteHmacBlock(output, hmacKey, 1, []);
        return output.ToArray();
    }

    public readonly record struct SampleEntry(string Title, string Username, string Password, string Url, string Notes, string Totp);

    private static byte[] InnerHeader(byte[] streamKey)
    {
        using var stream = new MemoryStream();
        WriteField32(stream, 1, UInt32Bytes(3));
        WriteField32(stream, 2, streamKey);
        WriteField32(stream, 0, []);
        return stream.ToArray();
    }

    private static string Xml(SampleEntry entry, bool protectPassword, uint streamId, byte[] streamKey)
    {
        var passwordXml = protectPassword
            ? ProtectedValue(entry.Password, streamId, streamKey)
            : Escape(entry.Password);
        var totp = string.IsNullOrEmpty(entry.Totp)
            ? string.Empty
            : $"<String><Key>otp</Key><Value>{Escape(entry.Totp)}</Value></String>";
        return $"""
            <?xml version="1.0" encoding="utf-8" standalone="yes"?>
            <KeePassFile>
              <Meta>
                <RecycleBinUUID>/////////////////////w==</RecycleBinUUID>
              </Meta>
              <Root>
                <Group>
                  <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                  <Name>Root</Name>
                  <Entry>
                    <String><Key>Title</Key><Value>{Escape(entry.Title)}</Value></String>
                    <String><Key>UserName</Key><Value>{Escape(entry.Username)}</Value></String>
                    <String><Key>Password</Key><Value{(protectPassword ? " Protected=\"True\"" : "")}>{passwordXml}</Value></String>
                    <String><Key>URL</Key><Value>{Escape(entry.Url)}</Value></String>
                    <String><Key>Notes</Key><Value>{Escape(entry.Notes)}</Value></String>
                    {totp}
                  </Entry>
                  <Group>
                    <UUID>/////////////////////w==</UUID>
                    <Name>Recycle Bin</Name>
                    <Entry>
                      <String><Key>Title</Key><Value>Trashed</Value></String>
                      <String><Key>Password</Key><Value>should-skip</Value></String>
                    </Entry>
                  </Group>
                </Group>
              </Root>
            </KeePassFile>
            """;
    }

    private static string ProtectedValue(string password, uint streamId, byte[] streamKey)
    {
        var utf8 = Encoding.UTF8.GetBytes(password);
        var cipher = streamId == 2
            ? KeePassStreamCipher.Salsa20(streamKey, utf8)
            : KeePassStreamCipher.InnerChaCha20(streamKey, utf8);
        return Convert.ToBase64String(cipher);
    }

    private static string Escape(string value) =>
        value.Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal);

    private static byte[] HashedBlocks(byte[] xml)
    {
        using var output = new MemoryStream();
        output.Write(UInt32Bytes(0));
        output.Write(SHA256.HashData(xml));
        output.Write(Int32Bytes(xml.Length));
        output.Write(xml);
        output.Write(UInt32Bytes(1));
        output.Write(new byte[32]);
        output.Write(Int32Bytes(0));
        return output.ToArray();
    }

    private static void WriteHmacBlock(Stream output, byte[] hmacKey, ulong index, byte[] data)
    {
        var message = new byte[12 + data.Length];
        BinaryPrimitives.WriteUInt64LittleEndian(message, index);
        BinaryPrimitives.WriteInt32LittleEndian(message.AsSpan(8), data.Length);
        data.CopyTo(message.AsSpan(12));
        var key = BlockKey(hmacKey, index);
        output.Write(Hmac(key, message));
        output.Write(Int32Bytes(data.Length));
        output.Write(data);
    }

    private static byte[] BlockKey(byte[] hmacKey, ulong index)
    {
        var buffer = new byte[8 + hmacKey.Length];
        BinaryPrimitives.WriteUInt64LittleEndian(buffer, index);
        hmacKey.CopyTo(buffer.AsSpan(8));
        return SHA512.HashData(buffer);
    }

    private static byte[] Hmac(byte[] key, byte[] data)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }

    private static byte[] Composite(string password)
    {
        var utf8 = Encoding.UTF8.GetBytes(password);
        return SHA256.HashData(SHA256.HashData(utf8));
    }

    private static byte[] AesKdfTransform(byte[] composite, byte[] seed, ulong rounds)
    {
        var block = composite.ToArray();
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = seed;
        using var encryptor = aes.CreateEncryptor();
        for (ulong i = 0; i < rounds; i++)
        {
            encryptor.TransformBlock(block, 0, 16, block, 0);
            encryptor.TransformBlock(block, 16, 16, block, 16);
        }

        return SHA256.HashData(block);
    }

    private static byte[] Argon2idTransform(byte[] composite, byte[] salt, ulong memoryBytes, uint iterations, int parallelism)
    {
        using var argon = new Argon2id(composite)
        {
            Salt = salt,
            Iterations = (int)iterations,
            MemorySize = (int)(memoryBytes / 1024),
            DegreeOfParallelism = parallelism
        };
        return argon.GetBytes(32);
    }

    private static byte[] AesCbcEncrypt(byte[] key, byte[] iv, byte[] plain)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(plain, 0, plain.Length);
    }

    private static byte[] AesKdfParameters(byte[] seed, ulong rounds)
    {
        using var stream = new MemoryStream();
        stream.Write(UInt16Bytes(0x0100));
        WriteVariant(stream, 0x42, "$UUID", AesKdf);
        WriteVariant(stream, 0x05, "R", UInt64Bytes(rounds));
        WriteVariant(stream, 0x42, "S", seed);
        stream.WriteByte(0);
        return stream.ToArray();
    }

    private static byte[] Argon2Parameters(byte[] salt, ulong memory, uint iterations, uint parallelism)
    {
        using var stream = new MemoryStream();
        stream.Write(UInt16Bytes(0x0100));
        WriteVariant(stream, 0x42, "$UUID", Argon2id);
        WriteVariant(stream, 0x05, "I", UInt64Bytes(iterations));
        WriteVariant(stream, 0x05, "M", UInt64Bytes(memory));
        WriteVariant(stream, 0x04, "P", UInt32Bytes(parallelism));
        WriteVariant(stream, 0x42, "S", salt);
        WriteVariant(stream, 0x04, "V", UInt32Bytes(0x13));
        stream.WriteByte(0);
        return stream.ToArray();
    }

    private static void WriteVariant(Stream stream, byte type, string key, byte[] value)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        stream.WriteByte(type);
        stream.Write(Int32Bytes(keyBytes.Length));
        stream.Write(keyBytes);
        stream.Write(Int32Bytes(value.Length));
        stream.Write(value);
    }

    private static void WriteSignature(Stream stream, ushort major, ushort minor)
    {
        stream.Write(UInt32Bytes(0x9AA2D903));
        stream.Write(UInt32Bytes(0xB54BFB67));
        stream.Write(UInt16Bytes(minor));
        stream.Write(UInt16Bytes(major));
    }

    private static void WriteField16(Stream stream, byte type, byte[] value)
    {
        stream.WriteByte(type);
        stream.Write(UInt16Bytes((ushort)value.Length));
        stream.Write(value);
    }

    private static void WriteField32(Stream stream, byte type, byte[] value)
    {
        stream.WriteByte(type);
        stream.Write(Int32Bytes(value.Length));
        stream.Write(value);
    }

    private static byte[] RandomBytes(int length)
    {
        var data = new byte[length];
        RandomNumberGenerator.Fill(data);
        return data;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        using var stream = new MemoryStream();
        foreach (var part in parts)
        {
            stream.Write(part);
        }

        return stream.ToArray();
    }

    private static byte[] UInt16Bytes(ushort value)
    {
        var data = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(data, value);
        return data;
    }

    private static byte[] UInt32Bytes(uint value)
    {
        var data = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(data, value);
        return data;
    }

    private static byte[] Int32Bytes(int value)
    {
        var data = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(data, value);
        return data;
    }

    private static byte[] UInt64Bytes(ulong value)
    {
        var data = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(data, value);
        return data;
    }
}
