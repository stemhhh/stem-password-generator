using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public sealed record SecretCheckReport(
    PasswordStrength Strength,
    double EntropyBits,
    string KindLabel,
    string Summary,
    string EntropyLabel,
    string CrackTimeLabel,
    IReadOnlyList<string> Findings,
    IReadOnlyList<string> NextSteps)
{
    public static SecretCheckReport Empty { get; } = new(
        PasswordStrength.Weak,
        0,
        string.Empty,
        string.Empty,
        string.Empty,
        string.Empty,
        [],
        []);
}

public static class SecretCheckService
{
    private const int MaximumSecretLength = 256;

    private static readonly HashSet<string> CommonSecrets = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "password1", "password123", "passw0rd", "p@ssw0rd", "p@ssword",
        "123456", "1234567", "12345678", "123456789", "1234567890", "1234", "12345",
        "111111", "000000", "654321", "qwerty", "qwerty123", "qwertyuiop", "asdfgh",
        "abc123", "letmein", "welcome", "admin", "admin123", "root", "login",
        "iloveyou", "monkey", "dragon", "master", "shadow", "sunshine", "princess",
        "football", "baseball", "soccer", "starwars", "superman", "batman",
        "summer", "winter", "spring", "autumn", "secret", "changeme",
        "contraseña", "contrasena", "clave", "clave123", "password!", "hola123",
        "mexico", "españa", "espana"
    };

    private static readonly string[] Sequences =
    [
        "0123456789",
        "9876543210",
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1qaz2wsx"
    ];

    public static SecretCheckReport Analyze(string? secret)
    {
        var text = secret ?? string.Empty;
        if (text.Length > MaximumSecretLength)
        {
            text = text[..MaximumSecretLength];
        }

        if (string.IsNullOrEmpty(text))
        {
            return SecretCheckReport.Empty;
        }

        var scan = Scan(text);
        var words = SplitWords(text);
        var phrase = LooksLikePhrase(text, scan.Pin, words);
        var entropy = scan.Pin ? PinEntropy(text) : text.Length * Math.Log2(scan.Pool);
        entropy = ApplyPenalties(scan, words, phrase, entropy, text.Length);

        var findings = new List<string>();
        CollectFindings(text, words, scan, phrase, findings);
        if (entropy < 28)
        {
            AddUnique(findings, UiStrings.Get("CheckFindingGuessable"));
        }

        var strength = StrengthFrom(entropy, findings.Count);
        return new SecretCheckReport(
            strength,
            entropy,
            scan.Pin ? UiStrings.Get("CheckKindPin") : phrase ? UiStrings.Get("CheckKindPhrase") : UiStrings.Get("CheckKindPassword"),
            Summary(strength, scan.Pin, phrase),
            UiStrings.Format("EntropyBitsOf", Math.Round(entropy).ToString("0")),
            CrackTimeFormatter.Label(entropy),
            findings,
            NextSteps(scan.Pin, phrase, text.Length, strength));
    }

    private static PasswordStrength StrengthFrom(double entropy, int findingCount)
    {
        var strength = entropy switch
        {
            >= 80 => PasswordStrength.Excellent,
            >= 60 => PasswordStrength.Strong,
            >= 40 => PasswordStrength.Medium,
            _ => PasswordStrength.Weak
        };

        if (findingCount >= 3 && strength > PasswordStrength.Medium)
        {
            strength = PasswordStrength.Medium;
        }

        if (findingCount >= 5)
        {
            strength = PasswordStrength.Weak;
        }

        return strength;
    }

    private static string Summary(PasswordStrength strength, bool pin, bool phrase) => (strength, pin, phrase) switch
    {
        (PasswordStrength.Excellent, _, true) => UiStrings.Get("CheckSummaryExcellentPhrase"),
        (PasswordStrength.Excellent, _, _) => UiStrings.Get("CheckSummaryExcellent"),
        (PasswordStrength.Strong, true, _) => UiStrings.Get("CheckSummaryStrongPin"),
        (PasswordStrength.Strong, _, _) => UiStrings.Get("CheckSummaryStrong"),
        (PasswordStrength.Medium, true, _) => UiStrings.Get("CheckSummaryMediumPin"),
        (PasswordStrength.Medium, _, _) => UiStrings.Get("CheckSummaryMedium"),
        (_, true, _) => UiStrings.Get("CheckSummaryWeakPin"),
        _ => UiStrings.Get("CheckSummaryWeak")
    };

    private static List<string> NextSteps(bool pin, bool phrase, int length, PasswordStrength strength)
    {
        var steps = new List<string>();
        if (strength is PasswordStrength.Weak or PasswordStrength.Medium)
        {
            steps.Add(UiStrings.Get("CheckNextGenerate"));
        }

        if (pin)
        {
            steps.Add(UiStrings.Get("CheckNextPin"));
        }
        else if (phrase && length < 24)
        {
            steps.Add(UiStrings.Get("CheckNextPhrase"));
        }
        else if (!phrase && length < 16)
        {
            steps.Add(UiStrings.Get("CheckNextLength"));
        }

        steps.Add(UiStrings.Get("CheckNextUnique"));
        steps.Add(UiStrings.Get("CheckNext2fa"));
        return steps;
    }

    private static void CollectFindings(string text, IReadOnlyList<string> words, SecretScan scan, bool phrase, List<string> findings)
    {
        if (scan.Common)
        {
            AddUnique(findings, UiStrings.Get("CheckFindingCommon"));
        }

        if (scan.Sequence)
        {
            AddUnique(findings, UiStrings.Get("CheckFindingSequence"));
        }

        if (scan.Repeat)
        {
            AddUnique(findings, UiStrings.Get("CheckFindingRepeat"));
        }

        if (scan.Year)
        {
            AddUnique(findings, UiStrings.Get("CheckFindingYear"));
        }

        if (scan.Pin)
        {
            if (text.Length < 6)
            {
                AddUnique(findings, UiStrings.Get("CheckFindingShortPin"));
            }
        }
        else if (!phrase && text.Length < 12)
        {
            AddUnique(findings, UiStrings.Get("CheckFindingShort"));
        }

        if (!scan.Pin && scan.Classes < 2)
        {
            AddUnique(findings, UiStrings.Get("CheckFindingClasses"));
        }

        if (phrase && words.Count < 4)
        {
            AddUnique(findings, UiStrings.Get("CheckFindingFewWords"));
        }

        if (phrase && words.All(static word => word.Length <= 3 || CommonSecrets.Contains(word)))
        {
            AddUnique(findings, UiStrings.Get("CheckFindingCommonPhrase"));
        }

        if (scan.Unique < 4 && text.Length >= 4)
        {
            AddUnique(findings, UiStrings.Get("CheckFindingLowVariety"));
        }
    }

    private readonly struct SecretScan
    {
        public bool Pin { get; init; }
        public int Classes { get; init; }
        public int Unique { get; init; }
        public int Pool { get; init; }
        public bool Sequence { get; init; }
        public bool Repeat { get; init; }
        public bool Year { get; init; }
        public bool Common { get; init; }
    }

    private static SecretScan Scan(string text)
    {
        var hasLower = false;
        var hasUpper = false;
        var hasDigit = false;
        var hasSymbol = false;
        var hasUnicode = false;
        var pin = true;
        var unique = new HashSet<char>(Math.Min(text.Length, 64));
        foreach (var character in text)
        {
            unique.Add(character);
            if (character > 127)
            {
                hasUnicode = true;
            }

            if (char.IsLower(character))
            {
                hasLower = true;
                pin = false;
            }
            else if (char.IsUpper(character))
            {
                hasUpper = true;
                pin = false;
            }
            else if (char.IsDigit(character))
            {
                hasDigit = true;
            }
            else
            {
                hasSymbol = true;
                pin = false;
            }
        }

        var classes = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);
        var pool = (hasLower ? 26 : 0) + (hasUpper ? 26 : 0) + (hasDigit ? 10 : 0) + (hasSymbol ? 25 : 0) + (hasUnicode ? 40 : 0);
        pool = Math.Max(2, pool);

        var common = CommonSecrets.Contains(text);
        if (!common && (char.IsWhiteSpace(text[0]) || char.IsWhiteSpace(text[^1])))
        {
            common = CommonSecrets.Contains(text.Trim());
        }

        var folded = pin ? text : text.ToLowerInvariant();
        return new SecretScan
        {
            Pin = pin,
            Classes = classes,
            Unique = unique.Count,
            Pool = pool,
            Sequence = HasSequence(folded),
            Repeat = HasRepeat(text),
            Year = LooksLikeYear(text),
            Common = common
        };
    }

    private static double PinEntropy(string secret) => secret.Length * Math.Log2(10);

    private static double ApplyPenalties(SecretScan scan, IReadOnlyList<string> words, bool phrase, double entropy, int length)
    {
        if (scan.Common)
        {
            return Math.Min(entropy, 12);
        }

        if (scan.Sequence || scan.Repeat || scan.Year)
        {
            entropy *= length >= 16 && !scan.Pin ? 0.85 : 0.45;
        }

        if (!scan.Pin && scan.Unique <= 3)
        {
            entropy *= 0.5;
        }

        if (phrase && words.Count >= 2 && words.All(static word => CommonSecrets.Contains(word) || word.Length <= 3))
        {
            entropy = Math.Min(entropy, 24);
        }

        return Math.Max(1, entropy);
    }

    private static bool HasSequence(string folded)
    {
        if (folded.Length < 4)
        {
            return false;
        }

        var run = folded.Length >= 16 ? 5 : 4;
        foreach (var sequence in Sequences)
        {
            if (sequence.Length < run)
            {
                continue;
            }

            for (var i = 0; i <= sequence.Length - run; i++)
            {
                if (folded.IndexOf(sequence.Substring(i, run), StringComparison.Ordinal) >= 0)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool HasRepeat(string text)
    {
        if (text.Length < 3)
        {
            return false;
        }

        var run = 1;
        for (var i = 1; i < text.Length; i++)
        {
            if (text[i] == text[i - 1])
            {
                run++;
                if (run >= 3)
                {
                    return true;
                }
            }
            else
            {
                run = 1;
            }
        }

        if (text.Length >= 6)
        {
            var half = text.Length / 2;
            if (text.AsSpan(0, half).SequenceEqual(text.AsSpan(half, half)))
            {
                return true;
            }
        }

        return false;
    }

    private static bool LooksLikeYear(string text)
    {
        if (text.Length is 4 && int.TryParse(text, out var year) && year is >= 1900 and <= 2099)
        {
            return true;
        }

        return text.Length is >= 4 and <= 10
            && int.TryParse(text.AsSpan(text.Length - 4), out year)
            && year is >= 1900 and <= 2099;
    }

    private static bool LooksLikePhrase(string text, bool pin, IReadOnlyList<string> words)
    {
        if (pin || words.Count < 2)
        {
            return false;
        }

        char? separator = null;
        foreach (var character in text)
        {
            if (char.IsWhiteSpace(character))
            {
                return true;
            }

            if (char.IsLetterOrDigit(character))
            {
                continue;
            }

            if (separator is null)
            {
                separator = character;
            }
            else if (character != separator)
            {
                return false;
            }
        }

        return separator is '-' or '_'
            && words.All(static word => word.All(char.IsLetter));
    }

    private static List<string> SplitWords(string text)
    {
        var words = new List<string>();
        var current = new System.Text.StringBuilder();
        foreach (var character in text)
        {
            if (char.IsLetterOrDigit(character))
            {
                current.Append(character);
                continue;
            }

            if (current.Length > 0)
            {
                words.Add(current.ToString());
                current.Clear();
            }
        }

        if (current.Length > 0)
        {
            words.Add(current.ToString());
        }

        return words;
    }

    private static void AddUnique(List<string> findings, string value)
    {
        if (!findings.Contains(value, StringComparer.Ordinal))
        {
            findings.Add(value);
        }
    }
}
