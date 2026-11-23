using Microsoft.UI.Xaml.Data;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Views;

public sealed class PasswordStrengthProgressConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        return value switch
        {
            PasswordStrength.Excellent => 100d,
            PasswordStrength.Strong => 75d,
            PasswordStrength.Medium => 50d,
            _ => 25d
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotSupportedException();
    }
}
