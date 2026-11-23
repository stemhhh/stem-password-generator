using Microsoft.UI.Xaml.Data;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Views;

public sealed class PasswordStrengthBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is not PasswordStrength strength)
        {
            return ThemeBrushCache.Get("TextFillColorTertiaryBrush");
        }

        if (parameter is string label && !MatchesStrengthLabel(strength, label))
        {
            return ThemeBrushCache.Get("TextFillColorTertiaryBrush");
        }

        return strength switch
        {
            PasswordStrength.Excellent => ThemeBrushCache.Get("AccentFillColorDefaultBrush"),
            PasswordStrength.Strong => ThemeBrushCache.Get("SystemFillColorSuccessBrush"),
            PasswordStrength.Medium => ThemeBrushCache.Get("SystemFillColorCautionBrush"),
            _ => ThemeBrushCache.Get("SystemFillColorCriticalBrush")
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotSupportedException();
    }

    private static bool MatchesStrengthLabel(PasswordStrength strength, string label) => label switch
    {
        "Weak" => strength == PasswordStrength.Weak,
        "Medium" => strength == PasswordStrength.Medium,
        "Strong" => strength == PasswordStrength.Strong,
        "Excellent" => strength == PasswordStrength.Excellent,
        _ => false
    };
}
