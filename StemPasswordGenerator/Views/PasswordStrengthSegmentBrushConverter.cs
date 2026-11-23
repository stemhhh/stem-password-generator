using Microsoft.UI.Xaml.Data;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Views;

public sealed class PasswordStrengthSegmentBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is not PasswordStrength strength ||
            !int.TryParse(parameter as string, out var segment) ||
            segment is < 1 or > 4)
        {
            return ThemeBrushCache.Get("SubtleFillColorSecondaryBrush");
        }

        var rank = strength switch
        {
            PasswordStrength.Excellent => 4,
            PasswordStrength.Strong => 3,
            PasswordStrength.Medium => 2,
            _ => 1
        };

        if (rank < segment)
        {
            return ThemeBrushCache.Get("SubtleFillColorSecondaryBrush");
        }

        return segment switch
        {
            1 => ThemeBrushCache.Get("SystemFillColorCriticalBrush"),
            2 => ThemeBrushCache.Get("SystemFillColorCautionBrush"),
            3 => ThemeBrushCache.Get("SystemFillColorSuccessBrush"),
            _ => ThemeBrushCache.Get("AccentFillColorDefaultBrush")
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotSupportedException();
    }
}
