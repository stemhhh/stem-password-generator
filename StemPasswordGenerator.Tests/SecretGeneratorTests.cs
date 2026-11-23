using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class SecretGeneratorTests
{
    private readonly SecretGenerator _generator = new();

    [Fact]
    public void Password_HasRequestedLengthAndCharacterClasses()
    {
        var options = PasswordOptions.CreateDefault() with { Length = 24 };
        var password = _generator.Generate(options);

        Assert.Equal(24, password.Length);
        Assert.Contains(password, char.IsUpper);
        Assert.Contains(password, char.IsLower);
        Assert.Contains(password, char.IsDigit);
        Assert.Contains(password, static c => !char.IsLetterOrDigit(c));
    }

    [Fact]
    public void Password_AvoidsAmbiguousCharacters()
    {
        var options = PasswordOptions.CreateDefault() with
        {
            Length = 48,
            AvoidAmbiguousCharacters = true,
            IncludeSymbols = false
        };

        var password = _generator.Generate(options);

        Assert.DoesNotContain('O', password);
        Assert.DoesNotContain('0', password);
        Assert.DoesNotContain('l', password);
        Assert.DoesNotContain('I', password);
        Assert.DoesNotContain('1', password);
    }

    [Fact]
    public void Password_ExcludesCustomCharacters()
    {
        var options = PasswordOptions.CreateDefault() with
        {
            Length = 32,
            IncludeSymbols = false,
            ExcludeCharacters = "Aa0"
        };

        var password = _generator.Generate(options);

        Assert.DoesNotContain('A', password);
        Assert.DoesNotContain('a', password);
        Assert.DoesNotContain('0', password);
    }

    [Fact]
    public void Password_NoRepeats_UsesUniqueCharacters()
    {
        var options = PasswordOptions.CreateDefault() with
        {
            Length = 20,
            NoRepeatedCharacters = true
        };

        var password = _generator.Generate(options);

        Assert.Equal(password.Length, password.Distinct().Count());
    }

    [Fact]
    public void Password_BeginsWithLetter()
    {
        var options = PasswordOptions.CreateDefault() with { BeginWithLetter = true };
        var password = _generator.Generate(options);
        Assert.True(char.IsLetter(password[0]));
    }

    [Fact]
    public void Passphrase_HasWordCountAndDigit()
    {
        var options = PasswordOptions.CreateDefault() with
        {
            Mode = GeneratorMode.Passphrase,
            Length = 5,
            WordSeparator = "-",
            CapitalizeWords = true,
            AppendDigit = true
        };

        var phrase = _generator.Generate(options);
        var parts = phrase.Split('-');

        Assert.Equal(6, parts.Length);
        Assert.True(parts.Take(5).All(static part => part.Length > 0 && char.IsUpper(part[0])));
        Assert.True(parts[^1].Length == 1 && char.IsDigit(parts[^1][0]));
    }

    [Fact]
    public void Pin_IsDigitsOfRequestedLength()
    {
        var options = PasswordOptions.CreateDefault() with
        {
            Mode = GeneratorMode.Pin,
            Length = 8
        };

        var pin = _generator.Generate(options);

        Assert.Equal(8, pin.Length);
        Assert.True(pin.All(char.IsDigit));
    }

    [Fact]
    public void WordList_HasEnoughUniqueWords()
    {
        Assert.True(WordList.Count >= 700);
    }
}

public sealed class PasswordStrengthServiceTests
{
    private readonly PasswordStrengthService _strength = new();
    private readonly SecretGenerator _generator = new();

    [Fact]
    public void ExtraLongPassword_IsExcellent()
    {
        var options = PasswordOptions.CreateDefault() with { Length = 32 };
        var secret = _generator.Generate(options);
        var report = _strength.Evaluate(secret, options);

        Assert.Equal(PasswordStrength.Excellent, report.Strength);
        Assert.True(report.EntropyBits >= 80);
    }

    [Fact]
    public void ShortPin_IsWeakOrMedium()
    {
        var options = PasswordOptions.CreateDefault() with
        {
            Mode = GeneratorMode.Pin,
            Length = 4
        };
        var report = _strength.Evaluate("1234", options);

        Assert.True(report.Strength is PasswordStrength.Weak or PasswordStrength.Medium);
    }
}
