namespace StemPasswordGenerator.Models;

public sealed record PasswordOptions(
    GeneratorMode Mode,
    int Length,
    bool IncludeUppercase,
    bool IncludeLowercase,
    bool IncludeNumbers,
    bool IncludeSymbols,
    bool AvoidAmbiguousCharacters,
    bool NoRepeatedCharacters,
    bool BeginWithLetter,
    string ExcludeCharacters,
    string WordSeparator,
    bool CapitalizeWords,
    bool AppendDigit)
{
    public const int MinimumPasswordLength = 8;
    public const int MaximumPasswordLength = 64;
    public const int DefaultPasswordLength = 20;
    public const int MinimumPinLength = 4;
    public const int MaximumPinLength = 12;
    public const int DefaultPinLength = 6;
    public const int MinimumWordCount = 3;
    public const int MaximumWordCount = 10;
    public const int DefaultWordCount = 6;
    public const int DefaultLength = DefaultPasswordLength;

    public static PasswordOptions CreateDefault()
    {
        return new PasswordOptions(
            GeneratorMode.Password,
            DefaultPasswordLength,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            string.Empty,
            "-",
            true,
            true);
    }

    public int MinimumLength => Mode switch
    {
        GeneratorMode.Pin => MinimumPinLength,
        GeneratorMode.Passphrase => MinimumWordCount,
        _ => MinimumPasswordLength
    };

    public int MaximumLength => Mode switch
    {
        GeneratorMode.Pin => MaximumPinLength,
        GeneratorMode.Passphrase => MaximumWordCount,
        _ => MaximumPasswordLength
    };

    public PasswordOptions Normalize()
    {
        var separator = string.IsNullOrEmpty(WordSeparator) ? "-" : WordSeparator[..1];
        var exclude = ExcludeCharacters ?? string.Empty;
        var length = Math.Clamp(Length, MinimumLength, MaximumLength);

        var includeUppercase = IncludeUppercase;
        var includeLowercase = IncludeLowercase;
        if (Mode == GeneratorMode.Password && BeginWithLetter && !includeUppercase && !includeLowercase)
        {
            includeLowercase = true;
        }

        return this with
        {
            Length = length,
            IncludeUppercase = includeUppercase,
            IncludeLowercase = includeLowercase,
            ExcludeCharacters = exclude,
            WordSeparator = separator
        };
    }
}
