using Microsoft.UI.Xaml.Data;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Views;

public sealed class PasswordStrengthLabelOpacityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is not PasswordStrength strength || parameter is not string label)
        {
            return 0.62d;
        }

        return string.Equals(strength.ToString(), label, StringComparison.OrdinalIgnoreCase)
            ? 1d
            : 0.62d;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotSupportedException();
    }
}
