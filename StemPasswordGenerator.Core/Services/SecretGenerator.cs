using System.Security.Cryptography;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public sealed class SecretGenerator
{
    private const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Lowercase = "abcdefghijklmnopqrstuvwxyz";
    private const string Numbers = "0123456789";
    private const string Symbols = "!@#$%^&*()-_=+[]{};:,.<>?";
    private static readonly HashSet<char> Ambiguous = ['O', '0', 'l', 'I', '1'];

    public string Generate(PasswordOptions options)
    {
        options = options.Normalize();
        return options.Mode switch
        {
            GeneratorMode.Passphrase => GeneratePassphrase(options),
            GeneratorMode.Pin => GeneratePin(options),
            _ => GeneratePassword(options)
        };
    }

    private static string GeneratePassword(PasswordOptions options)
    {
        var characterSets = GetCharacterSets(options);
        characterSets.RemoveAll(static set => set.Length == 0);

        if (characterSets.Count == 0)
        {
            return string.Empty;
        }

        var allCharacters = Combine(characterSets);
        if (allCharacters.Length == 0)
        {
            return string.Empty;
        }

        var length = options.Length;
        if (options.NoRepeatedCharacters)
        {
            length = Math.Min(length, allCharacters.Length);
        }

        if (length <= 0)
        {
            return string.Empty;
        }

        var password = new char[length];
        var used = options.NoRepeatedCharacters ? new HashSet<char>() : null;
        var index = 0;

        if (options.BeginWithLetter)
        {
            var letters = CombineLetters(characterSets);
            if (letters.Length > 0)
            {
                password[index++] = TakeRandom(letters, used);
            }
        }

        foreach (var characterSet in characterSets)
        {
            if (index >= password.Length)
            {
                break;
            }

            password[index++] = TakeRandom(characterSet, used);
        }

        while (index < password.Length)
        {
            password[index++] = TakeRandom(allCharacters, used);
        }

        Shuffle(password, options.BeginWithLetter ? 1 : 0);
        return new string(password);
    }

    private static string GeneratePin(PasswordOptions options)
    {
        var digits = FilterExcluded(Numbers, options.ExcludeCharacters, false);
        if (digits.Length == 0)
        {
            return string.Empty;
        }

        var length = options.NoRepeatedCharacters
            ? Math.Min(options.Length, digits.Length)
            : options.Length;
        var pin = new char[length];
        var used = options.NoRepeatedCharacters ? new HashSet<char>() : null;

        for (var i = 0; i < pin.Length; i++)
        {
            pin[i] = TakeRandom(digits, used);
        }

        return new string(pin);
    }

    private static string GeneratePassphrase(PasswordOptions options)
    {
        var words = WordList.Words;
        var count = words.Count;
        var parts = new string[options.AppendDigit ? options.Length + 1 : options.Length];
        for (var i = 0; i < options.Length; i++)
        {
            var word = words[RandomNumberGenerator.GetInt32(count)];
            parts[i] = options.CapitalizeWords
                ? char.ToUpperInvariant(word[0]) + word[1..]
                : word;
        }

        if (options.AppendDigit)
        {
            parts[^1] = RandomNumberGenerator.GetInt32(10).ToString();
        }

        return string.Join(options.WordSeparator, parts);
    }

    private static List<string> GetCharacterSets(PasswordOptions options)
    {
        var characterSets = new List<string>(4);
        var exclude = options.ExcludeCharacters;
        var avoid = options.AvoidAmbiguousCharacters;

        if (options.IncludeUppercase)
        {
            characterSets.Add(FilterExcluded(Uppercase, exclude, avoid));
        }

        if (options.IncludeLowercase)
        {
            characterSets.Add(FilterExcluded(Lowercase, exclude, avoid));
        }

        if (options.IncludeNumbers)
        {
            characterSets.Add(FilterExcluded(Numbers, exclude, avoid));
        }

        if (options.IncludeSymbols)
        {
            characterSets.Add(FilterExcluded(Symbols, exclude, false));
        }

        return characterSets;
    }

    private static string FilterExcluded(string characters, string exclude, bool avoidAmbiguous)
    {
        if (exclude.Length == 0 && !avoidAmbiguous)
        {
            return characters;
        }

        var filtered = new char[characters.Length];
        var count = 0;
        foreach (var character in characters)
        {
            if (avoidAmbiguous && Ambiguous.Contains(character))
            {
                continue;
            }

            if (exclude.Length > 0 && exclude.Contains(character, StringComparison.Ordinal))
            {
                continue;
            }

            filtered[count++] = character;
        }

        return count == characters.Length ? characters : new string(filtered, 0, count);
    }

    private static string Combine(List<string> characterSets)
    {
        if (characterSets.Count == 1)
        {
            return characterSets[0];
        }

        var length = 0;
        foreach (var characterSet in characterSets)
        {
            length += characterSet.Length;
        }

        return string.Create(length, characterSets, static (span, sets) =>
        {
            var offset = 0;
            foreach (var set in sets)
            {
                set.AsSpan().CopyTo(span[offset..]);
                offset += set.Length;
            }
        });
    }

    private static string CombineLetters(List<string> characterSets)
    {
        var letterSets = new List<string>(2);
        foreach (var set in characterSets)
        {
            if (set.Length > 0 && char.IsLetter(set[0]))
            {
                letterSets.Add(set);
            }
        }

        return letterSets.Count == 0 ? string.Empty : Combine(letterSets);
    }

    private static char TakeRandom(string characters, HashSet<char>? used)
    {
        if (used is null)
        {
            return characters[RandomNumberGenerator.GetInt32(characters.Length)];
        }

        var count = 0;
        Span<char> available = characters.Length <= 128
            ? stackalloc char[characters.Length]
            : new char[characters.Length];
        foreach (var character in characters)
        {
            if (!used.Contains(character))
            {
                available[count++] = character;
            }
        }

        if (count == 0)
        {
            return characters[RandomNumberGenerator.GetInt32(characters.Length)];
        }

        var chosen = available[RandomNumberGenerator.GetInt32(count)];
        used.Add(chosen);
        return chosen;
    }

    private static void Shuffle(char[] characters, int startIndex)
    {
        for (var i = characters.Length - 1; i > startIndex; i--)
        {
            var j = RandomNumberGenerator.GetInt32(startIndex, i + 1);
            (characters[i], characters[j]) = (characters[j], characters[i]);
        }
    }
}
