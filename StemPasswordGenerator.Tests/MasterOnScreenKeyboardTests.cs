using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class MasterOnScreenKeyboardTests
{
    [Fact]
    public void LettersPage_IsFixedQwerty()
    {
        var rows = MasterOnScreenKeyboard.Layout(MasterKeyboardPage.Letters, shift: false, capsLock: false);
        Assert.Equal("qwertyuiop", Characters(rows[0]));
        Assert.Equal("asdfghjkl", Characters(rows[1]));
        Assert.Equal("zxcvbnm", Characters(rows[2]));
        Assert.Contains(rows[2].Keys, static key => key.Kind is MasterKeyKind.Shift);
        Assert.Contains(rows[3].Keys, static key => key.Kind is MasterKeyKind.ToNumbers);
        Assert.Contains(rows[3].Keys, static key => key.Kind is MasterKeyKind.Space);
    }

    [Fact]
    public void TypingALetter_DoesNotMoveTheKeys()
    {
        var keyboard = new MasterKeyboardController();
        var before = Snapshot(keyboard.Rows);
        var typed = keyboard.Handle("q");
        Assert.Equal("q", typed.Insert);
        Assert.False(typed.LayoutChanged);
        Assert.Equal(before, Snapshot(keyboard.Rows));
    }

    [Fact]
    public void ShiftThenLetter_TypesACapitalThenReturnsToLowercase()
    {
        var keyboard = new MasterKeyboardController();
        Assert.True(keyboard.Handle(MasterOnScreenKeyboard.ShiftId).LayoutChanged);
        Assert.Equal("QWERTYUIOP", Characters(keyboard.Rows[0]));
        var typed = keyboard.Handle("Q");
        Assert.Equal("Q", typed.Insert);
        Assert.True(typed.LayoutChanged);
        Assert.False(keyboard.Shift);
        Assert.Equal("qwertyuiop", Characters(keyboard.Rows[0]));
    }

    [Fact]
    public void DoubleShift_StaysOnCapsLock()
    {
        var keyboard = new MasterKeyboardController();
        keyboard.Handle(MasterOnScreenKeyboard.ShiftId);
        keyboard.Handle(MasterOnScreenKeyboard.ShiftId);
        Assert.True(keyboard.CapsLock);
        Assert.Equal("A", keyboard.Handle("A").Insert);
        Assert.Equal("B", keyboard.Handle("B").Insert);
        Assert.True(keyboard.CapsLock);
        Assert.Equal("QWERTYUIOP", Characters(keyboard.Rows[0]));
        keyboard.Handle(MasterOnScreenKeyboard.ShiftId);
        Assert.False(keyboard.CapsLock);
        Assert.Equal("qwertyuiop", Characters(keyboard.Rows[0]));
    }

    [Fact]
    public void NumbersAndSymbols_StayPutAndCoverPasswordGlyphs()
    {
        var keyboard = new MasterKeyboardController();
        keyboard.Handle(MasterOnScreenKeyboard.NumbersId);
        Assert.Equal(MasterKeyboardPage.Numbers, keyboard.Page);
        Assert.Equal("1234567890", Characters(keyboard.Rows[0]));
        var numbers = Snapshot(keyboard.Rows);
        keyboard.Handle("7");
        Assert.Equal(numbers, Snapshot(keyboard.Rows));

        keyboard.Handle(MasterOnScreenKeyboard.SymbolsId);
        Assert.Equal("[]{}#%^*+=", Characters(keyboard.Rows[0]));
        Assert.Contains("_", Characters(keyboard.Rows[1]));
        keyboard.Handle(MasterOnScreenKeyboard.LettersId);
        Assert.Equal("qwertyuiop", Characters(keyboard.Rows[0]));
    }

    [Fact]
    public void SpaceAndBackspace_DoNotInsertAKeyId()
    {
        var keyboard = new MasterKeyboardController();
        Assert.Equal(" ", keyboard.Handle(MasterOnScreenKeyboard.SpaceId).Insert);
        var cut = keyboard.Handle(MasterOnScreenKeyboard.BackspaceId);
        Assert.True(cut.Backspace);
        Assert.Null(cut.Insert);
    }

    private static string Characters(MasterKeyboardRow row) =>
        string.Concat(row.Keys.Where(static key => key.Kind is MasterKeyKind.Character).Select(static key => key.Id));

    private static string Snapshot(IReadOnlyList<MasterKeyboardRow> rows) =>
        string.Join("|", rows.Select(static row => string.Join(",", row.Keys.Select(static key => key.Id))));
}
