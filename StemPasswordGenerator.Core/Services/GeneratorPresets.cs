using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class GeneratorPresets
{
    public static PasswordOptions? TryCreate(string? name)
    {
        return name switch
        {
            "Everyday" => new PasswordOptions(GeneratorMode.Password, 16, true, true, true, false, true, false, true, string.Empty, "-", true, true),
            "Strong" => new PasswordOptions(GeneratorMode.Password, 20, true, true, true, true, false, false, false, string.Empty, "-", true, true),
            "Extra" => new PasswordOptions(GeneratorMode.Password, 32, true, true, true, true, false, false, false, string.Empty, "-", true, true),
            "WiFi" => new PasswordOptions(GeneratorMode.Password, 20, true, true, true, true, true, false, true, string.Empty, "-", true, true),
            "Phrase" => new PasswordOptions(GeneratorMode.Passphrase, 6, true, true, true, true, false, false, false, string.Empty, "-", true, true),
            "PIN" => new PasswordOptions(GeneratorMode.Pin, 6, true, true, true, true, false, false, false, string.Empty, "-", true, true),
            _ => null
        };
    }

    public static bool CanGenerate(PasswordOptions options)
    {
        options = options.Normalize();
        return options.Mode switch
        {
            GeneratorMode.Passphrase => true,
            GeneratorMode.Pin => true,
            _ => options.IncludeUppercase || options.IncludeLowercase || options.IncludeNumbers || options.IncludeSymbols
        };
    }
}
