using Microsoft.Windows.Storage;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public sealed class UserPreferencesService
{
    private readonly ApplicationDataContainer _settings = ApplicationData.GetDefault().LocalSettings;

    public PasswordOptions LoadOptions()
    {
        var mode = (GeneratorMode)Math.Clamp(GetValue("Mode", 0), 0, 2);
        return new PasswordOptions(
            mode,
            PasswordOptions.DefaultPasswordLength,
            GetValue("IncludeUppercase", true),
            GetValue("IncludeLowercase", true),
            GetValue("IncludeNumbers", true),
            GetValue("IncludeSymbols", true),
            GetValue("AvoidAmbiguousCharacters", false),
            GetValue("NoRepeatedCharacters", false),
            GetValue("BeginWithLetter", false),
            GetValue("ExcludeCharacters", string.Empty),
            GetValue("WordSeparator", "-"),
            GetValue("CapitalizeWords", true),
            GetValue("AppendDigit", true)).Normalize();
    }

    public int LoadPasswordLength() => Math.Clamp(
        GetValue("PasswordLength", GetValue("Length", PasswordOptions.DefaultPasswordLength)),
        PasswordOptions.MinimumPasswordLength,
        PasswordOptions.MaximumPasswordLength);

    public int LoadPinLength() => Math.Clamp(GetValue("PinLength", PasswordOptions.DefaultPinLength), PasswordOptions.MinimumPinLength, PasswordOptions.MaximumPinLength);

    public int LoadWordCount() => Math.Clamp(GetValue("WordCount", PasswordOptions.DefaultWordCount), PasswordOptions.MinimumWordCount, PasswordOptions.MaximumWordCount);

    public void SaveOptions(PasswordOptions options, int passwordLength, int pinLength, int wordCount)
    {
        options = options.Normalize();
        _settings.Values["Mode"] = (int)options.Mode;
        _settings.Values["PasswordLength"] = passwordLength;
        _settings.Values["PinLength"] = pinLength;
        _settings.Values["WordCount"] = wordCount;
        _settings.Values["IncludeUppercase"] = options.IncludeUppercase;
        _settings.Values["IncludeLowercase"] = options.IncludeLowercase;
        _settings.Values["IncludeNumbers"] = options.IncludeNumbers;
        _settings.Values["IncludeSymbols"] = options.IncludeSymbols;
        _settings.Values["AvoidAmbiguousCharacters"] = options.AvoidAmbiguousCharacters;
        _settings.Values["NoRepeatedCharacters"] = options.NoRepeatedCharacters;
        _settings.Values["BeginWithLetter"] = options.BeginWithLetter;
        _settings.Values["ExcludeCharacters"] = options.ExcludeCharacters;
        _settings.Values["WordSeparator"] = options.WordSeparator;
        _settings.Values["CapitalizeWords"] = options.CapitalizeWords;
        _settings.Values["AppendDigit"] = options.AppendDigit;
    }

    public AppTheme LoadTheme() => (AppTheme)Math.Clamp(GetValue("Theme", 0), 0, 2);

    public bool LoadClearClipboard() => GetValue("ClearClipboard", true);

    public bool LoadAutoLockVault() => GetValue("AutoLockVault", true);

    public bool LoadOpenDecoyOnPanic() => GetValue("OpenDecoyOnPanic", false);

    public bool LoadStudentMode() => GetValue("StudentMode", true);

    public void SaveStudentMode(bool studentMode)
    {
        _settings.Values["StudentMode"] = studentMode;
    }

    public bool LoadStayInTray() => GetValue("StayInTray", true);

    public bool LoadGlobalHotkeys() => GetValue("GlobalHotkeys", true);

    public void SaveOpenDecoyOnPanic(bool openDecoyOnPanic)
    {
        _settings.Values["OpenDecoyOnPanic"] = openDecoyOnPanic;
    }

    public void SaveTray(bool stayInTray, bool globalHotkeys)
    {
        _settings.Values["StayInTray"] = stayInTray;
        _settings.Values["GlobalHotkeys"] = globalHotkeys;
    }

    public void SaveAppearance(AppTheme theme, bool clearClipboard, bool autoLockVault, AppLanguage language)
    {
        _settings.Values["Theme"] = (int)theme;
        _settings.Values["ClearClipboard"] = clearClipboard;
        _settings.Values["AutoLockVault"] = autoLockVault;
        _settings.Values["Language"] = (int)language;
    }

    public AppLanguage LoadLanguage()
    {
        if (_settings.Values.TryGetValue("Language", out var value) && value is int stored && stored is 0 or 1)
        {
            return (AppLanguage)stored;
        }

        var culture = System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
        return culture.Equals("es", StringComparison.OrdinalIgnoreCase) ? AppLanguage.Spanish : AppLanguage.English;
    }

    public void Clear()
    {
        _settings.Values.Clear();
    }

    private T GetValue<T>(string key, T fallback)
    {
        return _settings.Values.TryGetValue(key, out var value) && value is T typedValue
            ? typedValue
            : fallback;
    }
}
