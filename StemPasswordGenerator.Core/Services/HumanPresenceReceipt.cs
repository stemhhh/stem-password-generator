using System.Security.Cryptography;

namespace StemPasswordGenerator.Services;

public sealed class HumanPresenceReceipt : IDisposable
{
    private byte[]? _mac;

    internal HumanPresenceReceipt(byte[] mac)
    {
        _mac = mac ?? throw new ArgumentNullException(nameof(mac));
    }

    public static HumanPresenceReceipt ForBind(byte[] bind)
    {
        ArgumentNullException.ThrowIfNull(bind);
        return new HumanPresenceReceipt(HumanPresenceChallenge.MacFor(bind));
    }

    public bool IsConsumed => _mac is null;

    public bool Matches(byte[] grant)
    {
        if (_mac is null || grant.Length == 0)
        {
            return false;
        }

        var expected = HumanPresenceChallenge.MacFor(grant);
        try
        {
            return CryptographicOperations.FixedTimeEquals(_mac, expected);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    public void Dispose()
    {
        if (_mac is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_mac);
        _mac = null;
    }
}
