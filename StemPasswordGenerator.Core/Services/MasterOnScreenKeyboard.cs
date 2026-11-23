namespace StemPasswordGenerator.Services;

public enum MasterKeyboardPage
{
    Letters,
    Numbers,
    Symbols
}

public enum MasterKeyKind
{
    Character,
    Shift,
    Backspace,
    Space,
    ToNumbers,
    ToLetters,
    ToSymbols
}

public sealed record MasterKeyboardKey(
    MasterKeyKind Kind,
    string Id,
    string Label,
    double Flex,
    bool Highlighted = false);

public sealed record MasterKeyboardRow(
    IReadOnlyList<MasterKeyboardKey> Keys,
    double LeftSpacer = 0,
    double RightSpacer = 0);

public readonly record struct MasterKeyboardOutcome(string? Insert, bool Backspace, bool LayoutChanged)
{
    public static MasterKeyboardOutcome LayoutOnly { get; } = new(null, false, true);

    public static MasterKeyboardOutcome Delete { get; } = new(null, true, false);

    public static MasterKeyboardOutcome Type(string text) => new(text, false, false);
}

public static class MasterOnScreenKeyboard
{
    public const string ShiftId = "shift";
    public const string BackspaceId = "backspace";
    public const string SpaceId = "space";
    public const string NumbersId = "123";
    public const string LettersId = "ABC";
    public const string SymbolsId = "#+=";

    public static IReadOnlyList<MasterKeyboardRow> Layout(MasterKeyboardPage page, bool shift, bool capsLock)
    {
        var upper = shift || capsLock;
        return page switch
        {
            MasterKeyboardPage.Numbers => Numbers(),
            MasterKeyboardPage.Symbols => Symbols(),
            _ => Letters(upper, shift, capsLock)
        };
    }

    private static IReadOnlyList<MasterKeyboardRow> Letters(bool upper, bool shift, bool capsLock)
    {
        return
        [
            Row(Chars("qwertyuiop", upper)),
            new MasterKeyboardRow(Chars("asdfghjkl", upper), 0.45, 0.45),
            Row(
            [
                new MasterKeyboardKey(MasterKeyKind.Shift, ShiftId, capsLock ? "⇪" : "⇧", 1.45, shift || capsLock),
                ..Chars("zxcvbnm", upper),
                new MasterKeyboardKey(MasterKeyKind.Backspace, BackspaceId, "⌫", 1.45)
            ]),
            Row(
            [
                new MasterKeyboardKey(MasterKeyKind.ToNumbers, NumbersId, "123", 2.2),
                new MasterKeyboardKey(MasterKeyKind.Space, SpaceId, "space", 6)
            ])
        ];
    }

    private static IReadOnlyList<MasterKeyboardRow> Numbers()
    {
        return
        [
            Row(Chars("1234567890")),
            Row(Chars("-/:;()$&@\"")),
            Row(
            [
                new MasterKeyboardKey(MasterKeyKind.ToSymbols, SymbolsId, "#+=", 1.6),
                ..Chars(".,?!'"),
                new MasterKeyboardKey(MasterKeyKind.Backspace, BackspaceId, "⌫", 1.6)
            ]),
            Row(
            [
                new MasterKeyboardKey(MasterKeyKind.ToLetters, LettersId, "ABC", 2.2),
                new MasterKeyboardKey(MasterKeyKind.Space, SpaceId, "space", 6)
            ])
        ];
    }

    private static IReadOnlyList<MasterKeyboardRow> Symbols()
    {
        return
        [
            Row(Chars("[]{}#%^*+=")),
            Row(Chars("_\\|~<>€£¥•")),
            Row(
            [
                new MasterKeyboardKey(MasterKeyKind.ToNumbers, NumbersId, "123", 1.6),
                ..Chars(".,?!'"),
                new MasterKeyboardKey(MasterKeyKind.Backspace, BackspaceId, "⌫", 1.6)
            ]),
            Row(
            [
                new MasterKeyboardKey(MasterKeyKind.ToLetters, LettersId, "ABC", 2.2),
                new MasterKeyboardKey(MasterKeyKind.Space, SpaceId, "space", 6)
            ])
        ];
    }

    private static MasterKeyboardRow Row(IReadOnlyList<MasterKeyboardKey> keys) => new(keys);

    private static MasterKeyboardKey[] Chars(string glyphs, bool upper = false)
    {
        var keys = new MasterKeyboardKey[glyphs.Length];
        for (var i = 0; i < glyphs.Length; i++)
        {
            var glyph = upper ? char.ToUpperInvariant(glyphs[i]) : glyphs[i];
            var text = glyph.ToString();
            keys[i] = new MasterKeyboardKey(MasterKeyKind.Character, text, text, 1);
        }

        return keys;
    }
}

public sealed class MasterKeyboardController
{
    public MasterKeyboardPage Page { get; private set; } = MasterKeyboardPage.Letters;

    public bool Shift { get; private set; }

    public bool CapsLock { get; private set; }

    public IReadOnlyList<MasterKeyboardRow> Rows => MasterOnScreenKeyboard.Layout(Page, Shift, CapsLock);

    public void Reset()
    {
        Page = MasterKeyboardPage.Letters;
        Shift = false;
        CapsLock = false;
    }

    public MasterKeyboardOutcome Handle(string? id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return default;
        }

        switch (id)
        {
            case MasterOnScreenKeyboard.ShiftId:
                if (Page != MasterKeyboardPage.Letters)
                {
                    return default;
                }

                if (CapsLock)
                {
                    CapsLock = false;
                    Shift = false;
                }
                else if (Shift)
                {
                    CapsLock = true;
                }
                else
                {
                    Shift = true;
                }

                return MasterKeyboardOutcome.LayoutOnly;
            case MasterOnScreenKeyboard.BackspaceId:
                return MasterKeyboardOutcome.Delete;
            case MasterOnScreenKeyboard.SpaceId:
                return MasterKeyboardOutcome.Type(" ");
            case MasterOnScreenKeyboard.NumbersId:
                Page = MasterKeyboardPage.Numbers;
                Shift = false;
                CapsLock = false;
                return MasterKeyboardOutcome.LayoutOnly;
            case MasterOnScreenKeyboard.LettersId:
                Page = MasterKeyboardPage.Letters;
                return MasterKeyboardOutcome.LayoutOnly;
            case MasterOnScreenKeyboard.SymbolsId:
                Page = MasterKeyboardPage.Symbols;
                Shift = false;
                CapsLock = false;
                return MasterKeyboardOutcome.LayoutOnly;
            default:
                var consumeShift = Shift && !CapsLock && id.Length == 1 && char.IsLetter(id[0]);
                if (consumeShift)
                {
                    Shift = false;
                }

                return new MasterKeyboardOutcome(id, false, consumeShift);
        }
    }
}
