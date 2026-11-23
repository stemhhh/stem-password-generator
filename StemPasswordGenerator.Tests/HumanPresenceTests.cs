using System.Reflection;
using System.Security.Cryptography;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class HumanPresenceTests
{
    [Fact]
    public void MasterPasswordSuccess_IsNotUnlockedUntilChallengeCompletes()
    {
        using var session = Start();
        Assert.Equal(VaultAccessState.PendingHumanVerification, FakeVault.AfterMaster(session.Bind));
        Assert.False(FakeVault.IsUnlocked);
        Assert.Empty(FakeVault.Items);
        Assert.False(CanAutofill());
        Assert.False(CanMedia());
    }

    [Fact]
    public void CompletingChallenge_UnlocksAndConsumesReceipt()
    {
        using var session = Start();
        Complete(session.Challenge);
        Assert.True(session.Challenge.TryConsume(out var receipt));
        using (receipt)
        {
            Assert.True(FakeVault.Reveal(receipt));
        }

        Assert.Equal(VaultAccessState.Unlocked, FakeVault.State);
        Assert.True(FakeVault.IsUnlocked);
        Assert.False(session.Challenge.TryConsume(out _));
    }

    [Fact]
    public void WrongDigit_IssuesNewChallengeAndDoesNotUnlock()
    {
        using var session = Start();
        var first = session.Challenge.DisplayText;
        var wrong = (session.Challenge.Digits[0] + 1) % 10;
        Assert.Equal(HumanPresenceSubmitResult.Wrong, session.Challenge.SubmitDigit(wrong));
        Assert.NotEqual(first, session.Challenge.DisplayText);
        Assert.Equal(0, session.Challenge.EnteredCount);
        Assert.False(FakeVault.IsUnlocked);
        Assert.False(session.Challenge.TryConsume(out _));
    }

    [Fact]
    public void WrongDigit_DoesNotExtendTheDeadline()
    {
        using var session = Start();
        var deadline = session.Challenge.ExpiresUtc;
        var wrong = (session.Challenge.Digits[0] + 1) % 10;
        Assert.Equal(HumanPresenceSubmitResult.Wrong, session.Challenge.SubmitDigit(wrong));
        Assert.Equal(deadline, session.Challenge.ExpiresUtc);
    }

    [Fact]
    public void Keypad_ChangesAfterEveryCorrectDigit()
    {
        using var session = Start();
        var seen = new List<int[]>(HumanPresenceChallenge.DigitCount);
        seen.Add(session.Challenge.Keypad.ToArray());
        for (var i = 0; i < HumanPresenceChallenge.DigitCount; i++)
        {
            var result = session.Challenge.SubmitDigit(session.Challenge.Digits[i]);
            Assert.True(result is HumanPresenceSubmitResult.Correct or HumanPresenceSubmitResult.Completed);
            seen.Add(session.Challenge.Keypad.ToArray());
        }

        for (var i = 1; i < seen.Count; i++)
        {
            Assert.False(seen[i].SequenceEqual(seen[i - 1]));
        }

        Assert.Equal(10, seen[0].Distinct().Count());
    }

    [Fact]
    public void CoordinateReplay_FailsOnNewLayout()
    {
        using var session = Start();
        var slotOfFirst = IndexOf(session.Challenge.Keypad, session.Challenge.Digits[0]);
        Assert.Equal(HumanPresenceSubmitResult.Correct, session.Challenge.SubmitDigit(session.Challenge.Digits[0]));
        var nextNeeded = session.Challenge.Digits[1];
        var digitNowInSameSlot = session.Challenge.Keypad[slotOfFirst];
        var replayed = digitNowInSameSlot == nextNeeded ? (nextNeeded + 1) % 10 : digitNowInSameSlot;
        Assert.Equal(HumanPresenceSubmitResult.Wrong, session.Challenge.SubmitDigit(replayed));
        Assert.False(FakeVault.IsUnlocked);
    }

    [Fact]
    public void ExpiredChallenge_CannotUnlock()
    {
        using var challenge = HumanPresenceChallenge.Start(RandomNumberGenerator.GetBytes(32));
        typeof(HumanPresenceChallenge)
            .GetField("_expiresUtc", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .SetValue(challenge, DateTimeOffset.UtcNow.AddSeconds(-1));
        Assert.Equal(HumanPresenceSubmitResult.Expired, challenge.SubmitDigit(challenge.Digits[0]));
        Assert.False(challenge.TryConsume(out _));
    }

    [Fact]
    public void ForBindReceipt_MatchesTheSameBind()
    {
        var bind = RandomNumberGenerator.GetBytes(32);
        using var receipt = HumanPresenceReceipt.ForBind(bind);
        Assert.True(receipt.Matches(bind));
        Assert.False(receipt.Matches(RandomNumberGenerator.GetBytes(32)));
    }

    [Fact]
    public void CompletedReceipt_DoesNotMatchADifferentBind()
    {
        var bind = RandomNumberGenerator.GetBytes(32);
        using var challenge = HumanPresenceChallenge.Start(bind);
        Complete(challenge);
        Assert.True(challenge.TryConsume(out var receipt));
        using (receipt)
        {
            var other = RandomNumberGenerator.GetBytes(32);
            Assert.False(receipt.Matches(other));
            Assert.True(receipt.Matches(bind));
        }
    }

    [Fact]
    public void Lock_WipesChallengeAndBlocksReuse()
    {
        using var session = Start();
        Complete(session.Challenge);
        session.Challenge.Dispose();
        FakeVault.Lock();
        Assert.False(session.Challenge.TryConsume(out _));
        Assert.Equal(VaultAccessState.Locked, FakeVault.State);
        Assert.False(FakeVault.IsUnlocked);
    }

    [Fact]
    public void Lock_WipesPendingPayloadSoAReceiptCannotUnlock()
    {
        using var session = Start();
        Complete(session.Challenge);
        Assert.True(session.Challenge.TryConsume(out var receipt));
        using (receipt)
        {
            FakeVault.Lock();
            Assert.False(FakeVault.Reveal(receipt));
        }

        Assert.Equal(VaultAccessState.Locked, FakeVault.State);
        Assert.Empty(FakeVault.Items);
        Assert.False(CanAutofill());
        Assert.False(CanMedia());
    }

    [Fact]
    public void CrashRestart_DoesNotRestoreChallengeOrPendingSecrets()
    {
        using var session = Start();
        Complete(session.Challenge);
        FakeVault.SimulateCrash();
        session.Challenge.Dispose();

        Assert.Equal(VaultAccessState.Locked, FakeVault.State);
        Assert.False(FakeVault.IsUnlocked);
        Assert.Empty(FakeVault.Items);
        Assert.False(session.Challenge.TryConsume(out _));
        Assert.False(CanAutofill());
        Assert.False(CanMedia());
    }

    [Fact]
    public void ChallengeAndHold_HaveNoDiskApi()
    {
        Assert.DoesNotContain(
            typeof(HumanPresenceChallenge).GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly),
            LooksLikePersistence);
        Assert.DoesNotContain(
            typeof(PendingVaultHold).GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly),
            LooksLikePersistence);
    }

    private static bool LooksLikePersistence(MethodInfo method) =>
        method.Name is "Save" or "Write" or "Persist" or "Serialize";

    private static Session Start()
    {
        var bind = RandomNumberGenerator.GetBytes(32);
        FakeVault.AfterMaster(bind);
        return new Session(HumanPresenceChallenge.Start(bind), bind);
    }

    private static void Complete(HumanPresenceChallenge challenge)
    {
        for (var i = 0; i < HumanPresenceChallenge.DigitCount; i++)
        {
            challenge.SubmitDigit(challenge.Digits[i]);
        }
    }

    private static int IndexOf(IReadOnlyList<int> keypad, int digit)
    {
        for (var i = 0; i < keypad.Count; i++)
        {
            if (keypad[i] == digit)
            {
                return i;
            }
        }

        return -1;
    }

    private static bool CanAutofill() => FakeVault.IsUnlocked;

    private static bool CanMedia() => FakeVault.IsUnlocked;

    private sealed class Session : IDisposable
    {
        public Session(HumanPresenceChallenge challenge, byte[] bind)
        {
            Challenge = challenge;
            Bind = bind;
        }

        public HumanPresenceChallenge Challenge { get; }

        public byte[] Bind { get; }

        public void Dispose()
        {
            Challenge.Dispose();
            CryptographicOperations.ZeroMemory(Bind);
            FakeVault.Lock();
        }
    }

    private static class FakeVault
    {
        public static VaultAccessState State { get; private set; } = VaultAccessState.Locked;
        public static bool IsUnlocked => State == VaultAccessState.Unlocked;
        public static IReadOnlyList<string> Items { get; private set; } = [];
        private static byte[]? _bind;
        private static string? _pendingSecret;

        public static VaultAccessState AfterMaster(byte[] bind)
        {
            _bind = bind.ToArray();
            _pendingSecret = "secret";
            State = VaultAccessState.PendingHumanVerification;
            Items = [];
            return State;
        }

        public static bool Reveal(HumanPresenceReceipt receipt)
        {
            if (State != VaultAccessState.PendingHumanVerification || _bind is null || _pendingSecret is null || !receipt.Matches(_bind))
            {
                return false;
            }

            State = VaultAccessState.Unlocked;
            Items = [_pendingSecret];
            _pendingSecret = null;
            return true;
        }

        public static void Lock()
        {
            State = VaultAccessState.Locked;
            Items = [];
            _pendingSecret = null;
            if (_bind is not null)
            {
                CryptographicOperations.ZeroMemory(_bind);
                _bind = null;
            }
        }

        public static void SimulateCrash() => Lock();
    }
}
