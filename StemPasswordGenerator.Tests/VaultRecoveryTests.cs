using System.Security.Cryptography;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

[Collection("FastCrypto")]
public sealed class VaultRecoveryTests
{
    private const string Master = "correct-horse-battery-staple";

    [Fact]
    public void KeyAndPhrase_VerifyAgainstHashesOnly()
    {
        var materials = VaultRecovery.Create(Master);
        var verifier = VaultRecovery.CreateVerifier(materials);
        var blob = VaultRecovery.SerializeVerifier(verifier);

        Assert.StartsWith("STEMR-", materials.Key, StringComparison.Ordinal);
        Assert.Equal(7, materials.Phrase.Split(' ').Length);
        Assert.False(VaultRecovery.ContainsPlainSecrets(blob, materials));
        Assert.True(VaultRecovery.VerifyKey(materials.Key, verifier));
        Assert.True(VaultRecovery.VerifyPhrase(materials.Phrase, verifier));
        Assert.False(VaultRecovery.VerifyKey("STEMR-AAAAA-BBBBB-CCCCC-DDDDD", verifier));
        Assert.False(VaultRecovery.VerifyPhrase("wrong word list here now yes", verifier));
        Assert.NotEqual(VaultRecovery.NormalizePhrase(Master), materials.Phrase);
    }

    [Fact]
    public void Key_IgnoresDashesAndCase()
    {
        var materials = VaultRecovery.Create(Master);
        var verifier = VaultRecovery.CreateVerifier(materials);
        var packed = VaultRecovery.NormalizeKey(materials.Key);
        Assert.True(VaultRecovery.VerifyKey(packed.ToLowerInvariant(), verifier));
        Assert.True(VaultRecovery.LooksLikeKey(materials.Key));
    }

    [Fact]
    public void Phrase_IgnoresExtraSpacesAndHyphens()
    {
        var materials = VaultRecovery.Create(Master);
        var verifier = VaultRecovery.CreateVerifier(materials);
        var spaced = materials.Phrase.Replace(' ', '-');
        Assert.True(VaultRecovery.VerifyPhrase("  " + spaced + "  ", verifier));
    }

    [Fact]
    public void PasswordExport_RoundTrips_AndWrongPasswordFails()
    {
        var materials = VaultRecovery.Create(Master);
        const string extra = "export-file-pass-12";
        var blob = VaultRecovery.ProtectWithPassword(materials, extra);

        Assert.True(VaultRecovery.LooksLikePasswordExport(blob));
        Assert.False(VaultRecovery.ContainsPlainSecrets(blob, materials));
        var opened = VaultRecovery.OpenWithPassword(blob, extra);
        Assert.Equal(materials.Key, opened.Key);
        Assert.Equal(materials.Phrase, opened.Phrase);
        Assert.Throws<CryptographicException>(() => VaultRecovery.OpenWithPassword(blob, "wrong-export-12x"));
    }

    [Fact]
    public void PrintableKit_ContainsKeyAndPhrase_NotMaster()
    {
        var materials = VaultRecovery.Create(Master);
        var text = VaultRecovery.FormatPrintable(materials, "Enmanuel", DateTimeOffset.UnixEpoch);
        Assert.Contains(materials.Key, text, StringComparison.Ordinal);
        Assert.Contains(materials.Phrase, text, StringComparison.Ordinal);
        Assert.DoesNotContain(Master, text, StringComparison.Ordinal);
        Assert.Contains(VaultRecovery.FormatNumberedPhrase(materials.Phrase), text, StringComparison.Ordinal);
        Assert.Contains("Windows Hello", text, StringComparison.Ordinal);
    }

    [Fact]
    public void NumberedPhrase_ListsSevenWords()
    {
        var numbered = VaultRecovery.FormatNumberedPhrase("alpha bravo charlie delta echo foxtrot golf");
        Assert.Contains("1. alpha", numbered, StringComparison.Ordinal);
        Assert.Contains("7. golf", numbered, StringComparison.Ordinal);
        Assert.Equal(7, numbered.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).Length);
    }

    [Fact]
    public void VerifierMac_DetectsReplacement()
    {
        var materials = VaultRecovery.Create(Master);
        var blob = VaultRecovery.SerializeVerifier(VaultRecovery.CreateVerifier(materials));
        var key = RandomNumberGenerator.GetBytes(32);
        var mac = VaultRecovery.MacVerifier(blob, key);
        Assert.True(VaultRecovery.VerifyMac(blob, key, mac));
        blob[^1] ^= 0x01;
        Assert.False(VaultRecovery.VerifyMac(blob, key, mac));
    }

    [Fact]
    public void PhraseWords_ComeFromWordList()
    {
        var materials = VaultRecovery.Create(Master);
        foreach (var word in materials.Phrase.Split(' '))
        {
            Assert.Contains(word, WordList.Words);
        }
    }

    [Fact]
    public void TamperedVerifier_FailsClosed()
    {
        var materials = VaultRecovery.Create(Master);
        var blob = VaultRecovery.SerializeVerifier(VaultRecovery.CreateVerifier(materials));
        Assert.Throws<CryptographicException>(() => VaultRecovery.ParseVerifier("nope"u8.ToArray()));
        blob[5 + 16 + 9] ^= 0xFF;
        var parsed = VaultRecovery.ParseVerifier(blob);
        Assert.False(VaultRecovery.VerifyKey(materials.Key, parsed));
    }
}
