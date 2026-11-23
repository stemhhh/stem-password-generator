using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Konscious.Security.Cryptography;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class KeePassKdbxImporter
{
    public const int MaximumBytes = 32 * 1024 * 1024;
    public const int MaximumItems = 5000;

    private const uint Signature1 = 0x9AA2D903;
    private const uint Signature2 = 0xB54BFB67;
    private const ulong MaxAesKdfRounds = 2_000_000;
    private const ulong MaxArgon2Memory = 512UL * 1024 * 1024;

    private static readonly byte[] Aes256Cipher = Convert.FromHexString("31C1F2E6BF714350BE5805216AFC5AFF");
    private static readonly byte[] ChaCha20Cipher = Convert.FromHexString("D6038A2B8B6F4CB5A524339A31DBB59A");
    private static readonly byte[] AesKdfUuid = Convert.FromHexString("C9D9F39A628A4460BF740D08C18A4FEA");
    private static readonly byte[] Argon2dUuid = Convert.FromHexString("EF636DDF8C29444B91F7A9A403E30A0C");
    private static readonly byte[] Argon2idUuid = Convert.FromHexString("9E298B1956DB4773B23DFC3EC6F0A1E6");

    public static bool LooksLike(byte[] data) =>
        data is { Length: >= 12 }
        && BinaryPrimitives.ReadUInt32LittleEndian(data) == Signature1
        && BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4)) == Signature2;

    public static CsvVaultImportResult Open(byte[] data, string? password)
    {
        if (data is null || data.Length == 0)
        {
            return CsvVaultImportResult.Fail("CsvEmpty");
        }

        if (data.Length > MaximumBytes)
        {
            return CsvVaultImportResult.Fail("CsvTooLarge", MaximumBytes / (1024 * 1024));
        }

        if (!LooksLike(data))
        {
            return CsvVaultImportResult.Fail("KeePassDamaged");
        }

        if (string.IsNullOrEmpty(password))
        {
            return CsvVaultImportResult.Fail("KeePassNeedPassword");
        }

        byte[]? xmlBytes = null;
        try
        {
            var header = ReadHeader(data);
            var composite = CompositeKey(password);
            byte[] transformed;
            try
            {
                transformed = DeriveKey(header, composite);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(composite);
            }

            byte[] cipherKey;
            byte[] hmacKey;
            try
            {
                cipherKey = SHA256.HashData(Concat(header.MasterSeed, transformed));
                hmacKey = SHA512.HashData(Concat(header.MasterSeed, transformed, [1]));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(transformed);
            }

            try
            {
                xmlBytes = header.Major >= 4
                    ? DecryptV4(data, header, cipherKey, hmacKey)
                    : DecryptV3(data, header, cipherKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(cipherKey);
                CryptographicOperations.ZeroMemory(hmacKey);
            }

            return ParseXml(xmlBytes, header);
        }
        catch (KeePassImportException exception)
        {
            return CsvVaultImportResult.Fail(exception.Key, exception.Args);
        }
        catch (CryptographicException)
        {
            return CsvVaultImportResult.Fail("KeePassWrongPassword");
        }
        catch (InvalidDataException)
        {
            return CsvVaultImportResult.Fail("KeePassDamaged");
        }
        catch (FormatException)
        {
            return CsvVaultImportResult.Fail("KeePassDamaged");
        }
        catch (System.Xml.XmlException)
        {
            return CsvVaultImportResult.Fail("KeePassDamaged");
        }
        finally
        {
            if (xmlBytes is not null)
            {
                CryptographicOperations.ZeroMemory(xmlBytes);
            }
        }
    }

    private static Header ReadHeader(byte[] data)
    {
        var major = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(10));
        var minor = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(8));
        if (major is not 3 and not 4)
        {
            throw new KeePassImportException("KeePassUnsupported");
        }

        var header = new Header { Major = major, Minor = minor };
        var offset = 12;
        while (offset + 3 <= data.Length)
        {
            var type = data[offset];
            offset++;
            int size;
            if (major >= 4)
            {
                if (offset + 4 > data.Length)
                {
                    throw new KeePassImportException("KeePassDamaged");
                }

                size = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset));
                offset += 4;
            }
            else
            {
                if (offset + 2 > data.Length)
                {
                    throw new KeePassImportException("KeePassDamaged");
                }

                size = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset));
                offset += 2;
            }

            if (size < 0 || offset + size > data.Length)
            {
                throw new KeePassImportException("KeePassDamaged");
            }

            var value = data.AsSpan(offset, size).ToArray();
            offset += size;
            switch (type)
            {
                case 0:
                    header.End = offset;
                    return header;
                case 2:
                    header.CipherId = value;
                    break;
                case 3:
                    header.Compression = size >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(value) : 0;
                    break;
                case 4:
                    header.MasterSeed = value;
                    break;
                case 5:
                    header.TransformSeed = value;
                    break;
                case 6:
                    header.TransformRounds = size >= 8
                        ? BinaryPrimitives.ReadUInt64LittleEndian(value)
                        : size >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(value) : 0;
                    break;
                case 7:
                    header.EncryptionIv = value;
                    break;
                case 8:
                    header.ProtectedStreamKey = value;
                    break;
                case 9:
                    header.StreamStartBytes = value;
                    break;
                case 10:
                    header.InnerRandomStreamId = size >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(value) : 0;
                    break;
                case 11:
                    header.KdfParameters = value;
                    break;
            }
        }

        throw new KeePassImportException("KeePassDamaged");
    }

    private static byte[] CompositeKey(string password)
    {
        var utf8 = Encoding.UTF8.GetBytes(password);
        try
        {
            var inner = SHA256.HashData(utf8);
            try
            {
                return SHA256.HashData(inner);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(inner);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
        }
    }

    private static byte[] DeriveKey(Header header, byte[] composite)
    {
        if (header.Major >= 4)
        {
            if (header.KdfParameters is null)
            {
                throw new KeePassImportException("KeePassDamaged");
            }

            var map = VariantMap.Parse(header.KdfParameters);
            if (!map.TryGetBytes("$UUID", out var uuid))
            {
                throw new KeePassImportException("KeePassDamaged");
            }

            if (uuid.AsSpan().SequenceEqual(AesKdfUuid))
            {
                var rounds = map.GetUInt64("R");
                if (!map.TryGetBytes("S", out var seed))
                {
                    throw new KeePassImportException("KeePassDamaged");
                }

                return AesKdf(composite, seed, rounds);
            }

            if (uuid.AsSpan().SequenceEqual(Argon2idUuid) || uuid.AsSpan().SequenceEqual(Argon2dUuid))
            {
                return Argon2Kdf(composite, map, uuid.AsSpan().SequenceEqual(Argon2idUuid));
            }

            throw new KeePassImportException("KeePassUnsupported");
        }

        return AesKdf(composite, header.TransformSeed, header.TransformRounds);
    }

    private static byte[] AesKdf(byte[] composite, byte[] seed, ulong rounds)
    {
        if (seed.Length != 32 || rounds == 0 || rounds > MaxAesKdfRounds)
        {
            throw new KeePassImportException(rounds > MaxAesKdfRounds ? "KeePassHeavyKdf" : "KeePassDamaged");
        }

        var block = composite.ToArray();
        try
        {
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
        finally
        {
            CryptographicOperations.ZeroMemory(block);
        }
    }

    private static byte[] Argon2Kdf(byte[] composite, VariantMap map, bool id)
    {
        if (!map.TryGetBytes("S", out var salt))
        {
            throw new KeePassImportException("KeePassDamaged");
        }

        var iterations = (int)Math.Clamp(map.GetUInt64("I"), 1, int.MaxValue);
        var memory = map.GetUInt64("M");
        var parallelism = (int)Math.Clamp(map.GetUInt32("P"), 1, 16);
        if (memory < 8192 || memory > MaxArgon2Memory)
        {
            throw new KeePassImportException("KeePassHeavyKdf");
        }

        var memoryKiB = (int)(memory / 1024);
        Argon2 argon = id ? new Argon2id(composite) : new Argon2d(composite);
        using (argon)
        {
            argon.Salt = salt;
            argon.Iterations = iterations;
            argon.MemorySize = memoryKiB;
            argon.DegreeOfParallelism = parallelism;
            return argon.GetBytes(32);
        }
    }

    private static byte[] DecryptV3(byte[] data, Header header, byte[] cipherKey)
    {
        var cipher = DecryptPayload(header, cipherKey, data.AsSpan(header.End).ToArray());
        try
        {
            if (header.StreamStartBytes.Length == 0
                || cipher.Length < header.StreamStartBytes.Length
                || !cipher.AsSpan(0, header.StreamStartBytes.Length).SequenceEqual(header.StreamStartBytes))
            {
                throw new KeePassImportException("KeePassWrongPassword");
            }

            var packed = ReadHashedBlocks(cipher.AsSpan(header.StreamStartBytes.Length));
            return MaybeInflate(header, packed);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cipher);
        }
    }

    private static byte[] DecryptV4(byte[] data, Header header, byte[] cipherKey, byte[] hmacKey)
    {
        if (header.End + 64 > data.Length)
        {
            throw new KeePassImportException("KeePassDamaged");
        }

        var headerBytes = data.AsSpan(0, header.End);
        var storedHash = data.AsSpan(header.End, 32);
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(headerBytes), storedHash))
        {
            throw new KeePassImportException("KeePassDamaged");
        }

        var headerHmacKey = BlockHmacKey(hmacKey, ulong.MaxValue);
        try
        {
            var expected = HmacSha256(headerHmacKey, headerBytes.ToArray());
            if (!CryptographicOperations.FixedTimeEquals(expected, data.AsSpan(header.End + 32, 32)))
            {
                throw new KeePassImportException("KeePassWrongPassword");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(headerHmacKey);
        }

        var encrypted = ReadHmacBlocks(data.AsSpan(header.End + 64), hmacKey);
        try
        {
            return MaybeInflate(header, DecryptPayload(header, cipherKey, encrypted));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encrypted);
        }
    }

    private static byte[] DecryptPayload(Header header, byte[] cipherKey, byte[] encrypted)
    {
        if (header.CipherId.AsSpan().SequenceEqual(Aes256Cipher))
        {
            using var aes = Aes.Create();
            aes.Key = cipherKey;
            aes.IV = header.EncryptionIv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
        }

        if (header.CipherId.AsSpan().SequenceEqual(ChaCha20Cipher))
        {
            if (header.EncryptionIv.Length != 12)
            {
                throw new KeePassImportException("KeePassDamaged");
            }

            return KeePassStreamCipher.ChaCha20(cipherKey, header.EncryptionIv, encrypted);
        }

        throw new KeePassImportException("KeePassUnsupported");
    }

    private static byte[] MaybeInflate(Header header, byte[] payload)
    {
        if (header.Compression == 0)
        {
            return payload;
        }

        if (header.Compression != 1)
        {
            throw new KeePassImportException("KeePassUnsupported");
        }

        using var input = new MemoryStream(payload, writable: false);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzip.CopyTo(output);
        CryptographicOperations.ZeroMemory(payload);
        return output.ToArray();
    }

    private static byte[] ReadHashedBlocks(ReadOnlySpan<byte> data)
    {
        using var output = new MemoryStream();
        var offset = 0;
        uint expectedIndex = 0;
        while (offset + 40 <= data.Length)
        {
            var index = BinaryPrimitives.ReadUInt32LittleEndian(data[offset..]);
            offset += 4;
            var hash = data.Slice(offset, 32);
            offset += 32;
            var size = BinaryPrimitives.ReadInt32LittleEndian(data[offset..]);
            offset += 4;
            if (index != expectedIndex || size < 0)
            {
                throw new KeePassImportException("KeePassDamaged");
            }

            expectedIndex++;
            if (size == 0)
            {
                break;
            }

            if (offset + size > data.Length)
            {
                throw new KeePassImportException("KeePassDamaged");
            }

            var block = data.Slice(offset, size);
            offset += size;
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(block), hash))
            {
                throw new KeePassImportException("KeePassDamaged");
            }

            output.Write(block);
        }

        return output.ToArray();
    }

    private static byte[] ReadHmacBlocks(ReadOnlySpan<byte> data, byte[] hmacKey)
    {
        using var output = new MemoryStream();
        var offset = 0;
        ulong index = 0;
        while (offset + 36 <= data.Length)
        {
            var stored = data.Slice(offset, 32);
            offset += 32;
            var size = BinaryPrimitives.ReadInt32LittleEndian(data[offset..]);
            offset += 4;
            if (size < 0)
            {
                throw new KeePassImportException("KeePassDamaged");
            }

            var block = size == 0 ? ReadOnlySpan<byte>.Empty : data.Slice(offset, size);
            if (size > 0)
            {
                if (offset + size > data.Length)
                {
                    throw new KeePassImportException("KeePassDamaged");
                }

                offset += size;
            }

            var blockKey = BlockHmacKey(hmacKey, index);
            try
            {
                var message = new byte[12 + block.Length];
                BinaryPrimitives.WriteUInt64LittleEndian(message, index);
                BinaryPrimitives.WriteInt32LittleEndian(message.AsSpan(8), size);
                block.CopyTo(message.AsSpan(12));
                var expected = HmacSha256(blockKey, message);
                CryptographicOperations.ZeroMemory(message);
                if (!CryptographicOperations.FixedTimeEquals(expected, stored))
                {
                    throw new KeePassImportException("KeePassWrongPassword");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(blockKey);
            }

            if (size == 0)
            {
                break;
            }

            output.Write(block);
            index++;
        }

        return output.ToArray();
    }

    private static byte[] BlockHmacKey(byte[] hmacKey, ulong index)
    {
        var buffer = new byte[8 + hmacKey.Length];
        BinaryPrimitives.WriteUInt64LittleEndian(buffer, index);
        hmacKey.CopyTo(buffer.AsSpan(8));
        try
        {
            return SHA512.HashData(buffer);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static byte[] HmacSha256(byte[] key, byte[] data)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }

    private static CsvVaultImportResult ParseXml(byte[] payload, Header header)
    {
        uint streamId = header.InnerRandomStreamId;
        var streamKey = header.ProtectedStreamKey;
        var xmlBytes = payload;
        if (header.Major >= 4)
        {
            (streamId, streamKey, xmlBytes) = ReadInnerHeader(payload);
        }

        XDocument document;
        using (var stream = new MemoryStream(xmlBytes, writable: false))
        {
            document = XDocument.Load(stream);
        }

        UnprotectValues(document, streamId, streamKey);

        var recycle = document.Root?.Element("Meta")?.Element("RecycleBinUUID")?.Value ?? string.Empty;
        var root = document.Root?.Element("Root")?.Element("Group");
        if (root is null)
        {
            return CsvVaultImportResult.Fail("CsvEmpty");
        }

        var items = new List<VaultItem>();
        var skipped = 0;
        Collect(root, recycle, items, ref skipped);
        if (items.Count == 0)
        {
            return CsvVaultImportResult.Fail("CsvEmpty");
        }

        return new CsvVaultImportResult
        {
            Items = items,
            Skipped = skipped,
            Format = "keepass-kdbx"
        };
    }

    private static (uint StreamId, byte[] StreamKey, byte[] Xml) ReadInnerHeader(byte[] payload)
    {
        var offset = 0;
        uint streamId = 0;
        byte[] streamKey = [];
        while (offset + 5 <= payload.Length)
        {
            var type = payload[offset];
            offset++;
            var size = BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(offset));
            offset += 4;
            if (size < 0 || offset + size > payload.Length)
            {
                throw new KeePassImportException("KeePassDamaged");
            }

            var value = payload.AsSpan(offset, size).ToArray();
            offset += size;
            switch (type)
            {
                case 0:
                    return (streamId, streamKey, payload[offset..]);
                case 1:
                    streamId = size >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(value) : 0;
                    break;
                case 2:
                    streamKey = value;
                    break;
            }
        }

        throw new KeePassImportException("KeePassDamaged");
    }

    private static void UnprotectValues(XDocument document, uint streamId, byte[] streamKey)
    {
        if (streamId is 0 or 1)
        {
            if (streamId == 1)
            {
                throw new KeePassImportException("KeePassUnsupported");
            }

            return;
        }

        var protectedNodes = document.Descendants("Value")
            .Where(node => string.Equals((string?)node.Attribute("Protected"), "True", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (protectedNodes.Count == 0)
        {
            return;
        }

        var cipherLength = 0;
        var ciphertexts = new List<byte[]>(protectedNodes.Count);
        foreach (var node in protectedNodes)
        {
            var raw = string.IsNullOrWhiteSpace(node.Value) ? [] : Convert.FromBase64String(node.Value.Trim());
            ciphertexts.Add(raw);
            cipherLength += raw.Length;
        }

        var packed = new byte[cipherLength];
        var packedOffset = 0;
        foreach (var raw in ciphertexts)
        {
            raw.CopyTo(packed, packedOffset);
            packedOffset += raw.Length;
        }

        byte[] plain;
        if (streamId == 2)
        {
            plain = KeePassStreamCipher.Salsa20(streamKey, packed);
        }
        else if (streamId == 3)
        {
            plain = KeePassStreamCipher.InnerChaCha20(streamKey, packed);
        }
        else
        {
            throw new KeePassImportException("KeePassUnsupported");
        }

        try
        {
            var offset = 0;
            for (var i = 0; i < protectedNodes.Count; i++)
            {
                var length = ciphertexts[i].Length;
                protectedNodes[i].Value = Encoding.UTF8.GetString(plain, offset, length);
                offset += length;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(packed);
            CryptographicOperations.ZeroMemory(plain);
            foreach (var raw in ciphertexts)
            {
                CryptographicOperations.ZeroMemory(raw);
            }
        }
    }

    private static void Collect(XElement group, string recycleBin, List<VaultItem> items, ref int skipped)
    {
        var uuid = (string?)group.Element("UUID") ?? string.Empty;
        if (recycleBin.Length > 0 && uuid == recycleBin && recycleBin != "AAAAAAAAAAAAAAAAAAAAAA==")
        {
            return;
        }

        foreach (var entry in group.Elements("Entry"))
        {
            if (items.Count >= MaximumItems)
            {
                skipped++;
                continue;
            }

            var item = FromEntry(entry);
            if (item is null || !CanKeep(item) || CsvVaultImporter.IsDuplicate(item, items))
            {
                skipped++;
                continue;
            }

            items.Add(item);
        }

        foreach (var child in group.Elements("Group"))
        {
            Collect(child, recycleBin, items, ref skipped);
        }
    }

    private static VaultItem? FromEntry(XElement entry)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var node in entry.Elements("String"))
        {
            var key = (string?)node.Element("Key") ?? string.Empty;
            var value = (string?)node.Element("Value") ?? string.Empty;
            if (key.Length > 0 && !fields.ContainsKey(key))
            {
                fields[key] = value;
            }
        }

        fields.TryGetValue("Title", out var title);
        fields.TryGetValue("UserName", out var username);
        fields.TryGetValue("Password", out var password);
        fields.TryGetValue("URL", out var url);
        fields.TryGetValue("Notes", out var notes);
        title ??= string.Empty;
        username ??= string.Empty;
        password ??= string.Empty;
        url ??= string.Empty;
        notes ??= string.Empty;

        var totp = FirstNonEmpty(
            Field(fields, "otp"),
            Field(fields, "OTPAuth"),
            Field(fields, "TimeOtp-Secret-Base32"),
            Field(fields, "TimeOtp-Secret"));
        var parsedTotp = TotpService.TryParseOtpAuth(totp) ?? totp.Trim();

        if (string.IsNullOrWhiteSpace(password) && string.IsNullOrWhiteSpace(parsedTotp))
        {
            if (string.IsNullOrWhiteSpace(notes))
            {
                return null;
            }

            if (string.IsNullOrWhiteSpace(title))
            {
                title = UiStrings.Get("KindNote");
            }

            return new VaultItem
            {
                Kind = VaultItemKind.Note,
                Title = title.Trim(),
                Notes = notes
            };
        }

        if (string.IsNullOrWhiteSpace(title))
        {
            title = HostTitle(url);
        }

        if (string.IsNullOrWhiteSpace(title))
        {
            title = UiStrings.Get("ImportedLoginTitle");
        }

        return new VaultItem
        {
            Kind = VaultItemKind.Login,
            Title = title.Trim(),
            Url = FirstUri(url),
            Username = username.Trim(),
            Password = password,
            TotpSecret = parsedTotp,
            Notes = notes
        };
    }

    private static bool CanKeep(VaultItem item) =>
        VaultItemRules.CanSave(
            item.Kind,
            item.Title,
            item.Password,
            item.AliasEmail,
            item.CardNumber,
            item.Notes,
            item.FullName,
            item.Username);

    private static string Field(Dictionary<string, string> fields, string key) =>
        fields.TryGetValue(key, out var value) ? value : string.Empty;

    private static string FirstNonEmpty(params string[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static string HostTitle(string url)
    {
        if (Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
        {
            return uri.Host;
        }

        return url.Trim();
    }

    private static string FirstUri(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        var split = trimmed.IndexOfAny(['\n', ' ', ',']);
        return split < 0 ? trimmed : trimmed[..split].Trim();
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var length = 0;
        foreach (var part in parts)
        {
            length += part.Length;
        }

        var output = new byte[length];
        var offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(output, offset);
            offset += part.Length;
        }

        return output;
    }

    private sealed class Header
    {
        public int Major;
        public int Minor;
        public int End;
        public byte[] CipherId = [];
        public uint Compression;
        public byte[] MasterSeed = [];
        public byte[] TransformSeed = [];
        public ulong TransformRounds;
        public byte[] EncryptionIv = [];
        public byte[] ProtectedStreamKey = [];
        public byte[] StreamStartBytes = [];
        public uint InnerRandomStreamId;
        public byte[]? KdfParameters;
    }

    private sealed class VariantMap
    {
        private readonly Dictionary<string, (byte Type, byte[] Value)> _entries = new(StringComparer.Ordinal);

        public static VariantMap Parse(byte[] data)
        {
            if (data.Length < 3)
            {
                throw new KeePassImportException("KeePassDamaged");
            }

            var version = BinaryPrimitives.ReadUInt16LittleEndian(data);
            if ((version & 0xFF00) > 0x0100)
            {
                throw new KeePassImportException("KeePassUnsupported");
            }

            var map = new VariantMap();
            var offset = 2;
            while (offset < data.Length)
            {
                var type = data[offset];
                offset++;
                if (type == 0)
                {
                    return map;
                }

                if (offset + 4 > data.Length)
                {
                    throw new KeePassImportException("KeePassDamaged");
                }

                var keySize = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset));
                offset += 4;
                if (keySize < 0 || offset + keySize + 4 > data.Length)
                {
                    throw new KeePassImportException("KeePassDamaged");
                }

                var key = Encoding.UTF8.GetString(data, offset, keySize);
                offset += keySize;
                var valueSize = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset));
                offset += 4;
                if (valueSize < 0 || offset + valueSize > data.Length)
                {
                    throw new KeePassImportException("KeePassDamaged");
                }

                map._entries[key] = (type, data.AsSpan(offset, valueSize).ToArray());
                offset += valueSize;
            }

            return map;
        }

        public bool TryGetBytes(string key, out byte[] value)
        {
            if (_entries.TryGetValue(key, out var entry))
            {
                value = entry.Value;
                return true;
            }

            value = [];
            return false;
        }

        public ulong GetUInt64(string key)
        {
            if (!_entries.TryGetValue(key, out var entry))
            {
                return 0;
            }

            return entry.Type switch
            {
                0x05 when entry.Value.Length >= 8 => BinaryPrimitives.ReadUInt64LittleEndian(entry.Value),
                0x04 when entry.Value.Length >= 4 => BinaryPrimitives.ReadUInt32LittleEndian(entry.Value),
                _ => 0
            };
        }

        public uint GetUInt32(string key)
        {
            if (!_entries.TryGetValue(key, out var entry) || entry.Value.Length < 4)
            {
                return 0;
            }

            return BinaryPrimitives.ReadUInt32LittleEndian(entry.Value);
        }
    }

    private sealed class KeePassImportException : Exception
    {
        public KeePassImportException(string key, params object[] args)
            : base(key)
        {
            Key = key;
            Args = args;
        }

        public string Key { get; }

        public object[] Args { get; }
    }
}
