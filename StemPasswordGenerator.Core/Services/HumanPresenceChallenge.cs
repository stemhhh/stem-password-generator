using System.Security.Cryptography;

namespace StemPasswordGenerator.Services;

public enum HumanPresenceSubmitResult
{
    Correct,
    Completed,
    Wrong,
    Expired,
    Consumed,
    Invalid
}

public sealed class HumanPresenceChallenge : IDisposable
{
    public const int DigitCount = 6;
    public const int KeyCount = 10;
    public static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(90);
    private static readonly byte[] MacInfo = "STEM-HUMAN-OK"u8.ToArray();

    private readonly byte[] _bind;
    private readonly int[] _digits = new int[DigitCount];
    private readonly int[] _keypad = new int[KeyCount];
    private int[] _previousKeypad = new int[KeyCount];
    private int _entered;
    private bool _consumed;
    private DateTimeOffset _expiresUtc;

    private HumanPresenceChallenge(byte[] bind)
    {
        _bind = bind;
        RenewChallenge();
    }

    public static HumanPresenceChallenge Start(byte[] bindToken)
    {
        ArgumentNullException.ThrowIfNull(bindToken);
        if (bindToken.Length < 16)
        {
            throw new ArgumentException("The human-verification bind token is too short.", nameof(bindToken));
        }

        var copy = new byte[bindToken.Length];
        Buffer.BlockCopy(bindToken, 0, copy, 0, bindToken.Length);
        return new HumanPresenceChallenge(copy);
    }

    public DateTimeOffset ExpiresUtc => _expiresUtc;

    public bool IsExpired => DateTimeOffset.UtcNow >= _expiresUtc;

    public bool IsConsumed => _consumed;

    public bool IsComplete => _entered >= DigitCount && !_consumed && !IsExpired;

    public int EnteredCount => _entered;

    public string DisplayText
    {
        get
        {
            return $"{_digits[0]}{_digits[1]} {_digits[2]}{_digits[3]} {_digits[4]}{_digits[5]}";
        }
    }

    public IReadOnlyList<int> Digits => _digits;

    public IReadOnlyList<int> Keypad => _keypad;

    public HumanPresenceSubmitResult SubmitDigit(int digit)
    {
        if (_consumed)
        {
            return HumanPresenceSubmitResult.Consumed;
        }

        if (digit is < 0 or > 9)
        {
            return HumanPresenceSubmitResult.Invalid;
        }

        if (IsExpired)
        {
            return HumanPresenceSubmitResult.Expired;
        }

        if (digit != _digits[_entered])
        {
            RenewChallenge();
            return HumanPresenceSubmitResult.Wrong;
        }

        _entered++;
        ShuffleKeypad();
        return _entered >= DigitCount ? HumanPresenceSubmitResult.Completed : HumanPresenceSubmitResult.Correct;
    }

    public bool TryConsume(out HumanPresenceReceipt receipt)
    {
        receipt = null!;
        if (_consumed || !IsComplete)
        {
            return false;
        }

        _consumed = true;
        receipt = new HumanPresenceReceipt(MacFor(_bind));
        CryptographicOperations.ZeroMemory(_bind);
        return true;
    }

    public void Dispose()
    {
        _consumed = true;
        CryptographicOperations.ZeroMemory(_bind);
        Array.Clear(_digits);
        Array.Clear(_keypad);
        Array.Clear(_previousKeypad);
        _entered = 0;
    }

    internal static byte[] MacFor(byte[] grant)
    {
        using var hmac = new HMACSHA256(grant);
        return hmac.ComputeHash(MacInfo);
    }

    private void RenewChallenge()
    {
        _entered = 0;
        if (_expiresUtc == default)
        {
            _expiresUtc = DateTimeOffset.UtcNow.Add(Lifetime);
        }

        for (var i = 0; i < DigitCount; i++)
        {
            _digits[i] = RandomNumberGenerator.GetInt32(10);
        }

        ShuffleKeypad();
    }

    private void ShuffleKeypad()
    {
        _keypad.CopyTo(_previousKeypad, 0);
        for (var attempt = 0; attempt < 16; attempt++)
        {
            for (var i = 0; i < KeyCount; i++)
            {
                _keypad[i] = i;
            }

            for (var i = KeyCount - 1; i > 0; i--)
            {
                var j = RandomNumberGenerator.GetInt32(i + 1);
                (_keypad[i], _keypad[j]) = (_keypad[j], _keypad[i]);
            }

            if (!SameLayout(_keypad, _previousKeypad))
            {
                return;
            }
        }
    }

    private static bool SameLayout(int[] left, int[] right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        for (var i = 0; i < left.Length; i++)
        {
            if (left[i] != right[i])
            {
                return false;
            }
        }

        return true;
    }
}
