using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public sealed class PasswordStrengthService
{
    public StrengthReport Evaluate(string secret, PasswordOptions options)
    {
        options = options.Normalize();
        if (string.IsNullOrEmpty(secret))
        {
            return new StrengthReport(
                PasswordStrength.Weak,
                0,
                UiStrings.Format("EntropyBits", 0),
                UiStrings.Get("Instant"),
                UiStrings.Get("SelectCharacterGroup"));
        }

        var entropy = options.Mode switch
        {
            GeneratorMode.Passphrase => EstimatePassphraseEntropy(options),
            GeneratorMode.Pin => EstimatePinEntropy(secret, options),
            _ => EstimatePasswordEntropy(secret, options)
        };

        var strength = entropy switch
        {
            >= 80 => PasswordStrength.Excellent,
            >= 60 => PasswordStrength.Strong,
            >= 40 => PasswordStrength.Medium,
            _ => PasswordStrength.Weak
        };

        return new StrengthReport(
            strength,
            entropy,
            UiStrings.Format("EntropyBitsOf", Math.Round(entropy).ToString("0")),
            CrackTimeFormatter.Label(entropy),
            Describe(strength, options.Mode));
    }

    private static double EstimatePasswordEntropy(string secret, PasswordOptions options)
    {
        var hasUpper = options.IncludeUppercase;
        var hasLower = options.IncludeLowercase;
        var hasDigit = options.IncludeNumbers;
        var hasSymbol = options.IncludeSymbols;
        foreach (var character in secret)
        {
            if (char.IsUpper(character))
            {
                hasUpper = true;
            }
            else if (char.IsLower(character))
            {
                hasLower = true;
            }
            else if (char.IsDigit(character))
            {
                hasDigit = true;
            }
            else
            {
                hasSymbol = true;
            }
        }

        var pool = 0;
        var ambiguous = options.AvoidAmbiguousCharacters;
        if (hasUpper)
        {
            pool += ambiguous ? 24 : 26;
        }

        if (hasLower)
        {
            pool += ambiguous ? 24 : 26;
        }

        if (hasDigit)
        {
            pool += ambiguous ? 8 : 10;
        }

        if (hasSymbol)
        {
            pool += 25;
        }

        pool = Math.Max(pool - CountExcluded(options.ExcludeCharacters), 2);
        var entropy = secret.Length * Math.Log2(pool);
        if (options.NoRepeatedCharacters && secret.Length > 1)
        {
            entropy *= 0.97;
        }

        return entropy;
    }

    private static double EstimatePinEntropy(string secret, PasswordOptions options)
    {
        var pool = Math.Max(2, 10 - CountExcluded(options.ExcludeCharacters));
        var entropy = secret.Length * Math.Log2(pool);
        if (options.NoRepeatedCharacters && secret.Length > 1)
        {
            entropy *= 0.92;
        }

        return entropy;
    }

    private static double EstimatePassphraseEntropy(PasswordOptions options)
    {
        var entropy = options.Length * Math.Log2(Math.Max(2, WordList.Count));
        if (options.AppendDigit)
        {
            entropy += Math.Log2(10);
        }

        return entropy;
    }

    private static int CountExcluded(string exclude)
    {
        return string.IsNullOrEmpty(exclude) ? 0 : exclude.Distinct().Count();
    }

    private static string Describe(PasswordStrength strength, GeneratorMode mode)
    {
        return (strength, mode) switch
        {
            (PasswordStrength.Excellent, GeneratorMode.Passphrase) => UiStrings.Get("DescribeExcellentPhrase"),
            (PasswordStrength.Excellent, _) => UiStrings.Get("DescribeExcellent"),
            (PasswordStrength.Strong, GeneratorMode.Pin) => UiStrings.Get("DescribeStrongPin"),
            (PasswordStrength.Strong, _) => UiStrings.Get("DescribeStrong"),
            (PasswordStrength.Medium, GeneratorMode.Pin) => UiStrings.Get("DescribeMediumPin"),
            (PasswordStrength.Medium, _) => UiStrings.Get("DescribeMedium"),
            (_, GeneratorMode.Pin) => UiStrings.Get("DescribeWeakPin"),
            _ => UiStrings.Get("DescribeWeak")
        };
    }
}
