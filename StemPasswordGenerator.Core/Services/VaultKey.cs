using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace StemPasswordGenerator.Services;

public sealed class VaultKey : IDisposable
{
    private readonly object _gate = new();
    private readonly int _keyLength;
    private byte[]? _key;
    private GCHandle _pin;
    private bool _protected;
    private bool _locked;

    internal VaultKey(byte[] key, byte[] salt, int memoryKiB, int iterations, int parallelism)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(salt);
        if (key.Length != 32)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new ArgumentException("The vault key must be 32 bytes.", nameof(key));
        }

        _keyLength = key.Length;
        _key = new byte[ProtectedMemory.AlignedLength(key.Length)];
        key.CopyTo(_key, 0);
        CryptographicOperations.ZeroMemory(key);
        Salt = salt;
        MemoryKiB = memoryKiB;
        Iterations = iterations;
        Parallelism = parallelism;
        _pin = GCHandle.Alloc(_key, GCHandleType.Pinned);
        _locked = ProtectedMemory.TryLock(_pin.AddrOfPinnedObject(), _key.Length);
        _protected = ProtectedMemory.TryProtect(_key);
    }

    public static VaultKey FromStored(byte[] key, byte[] salt, int memoryKiB, int iterations, int parallelism)
    {
        return new VaultKey(key, salt, memoryKiB, iterations, parallelism);
    }

    public byte[] Salt { get; }

    public int MemoryKiB { get; }

    public int Iterations { get; }

    public int Parallelism { get; }

    public bool IsDisposed
    {
        get
        {
            lock (_gate)
            {
                return _key is null;
            }
        }
    }

    public byte[] CopyKeyBytes()
    {
        return UseKey(key =>
        {
            var copy = new byte[_keyLength];
            Buffer.BlockCopy(key, 0, copy, 0, _keyLength);
            return copy;
        });
    }

    internal T UseKey<T>(Func<byte[], T> use)
    {
        ArgumentNullException.ThrowIfNull(use);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_key is null, this);
            Reveal();
            try
            {
                return use(_key);
            }
            finally
            {
                Conceal();
            }
        }
    }

    internal void UseKey(Action<byte[]> use)
    {
        ArgumentNullException.ThrowIfNull(use);
        UseKey(key =>
        {
            use(key);
            return 0;
        });
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    ~VaultKey() => Dispose(disposing: false);

    private void Dispose(bool disposing)
    {
        lock (_gate)
        {
            if (_key is null)
            {
                return;
            }

            Reveal();
            ProtectedMemory.Zero(_key);
            if (_locked && _pin.IsAllocated)
            {
                ProtectedMemory.Unlock(_pin.AddrOfPinnedObject(), _key.Length);
            }

            if (_pin.IsAllocated)
            {
                _pin.Free();
            }

            _key = null;
            _protected = false;
            _locked = false;
        }
    }

    private void Reveal()
    {
        if (_protected && _key is not null)
        {
            if (!ProtectedMemory.TryUnprotect(_key))
            {
                throw new CryptographicException("The vault key could not be unsealed in memory.");
            }

            _protected = false;
        }
    }

    private void Conceal()
    {
        if (_key is null || _protected)
        {
            return;
        }

        _protected = ProtectedMemory.TryProtect(_key);
    }
}
