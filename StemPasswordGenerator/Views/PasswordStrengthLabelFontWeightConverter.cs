using Microsoft.UI.Xaml.Data;
using StemPasswordGenerator.Models;
using Windows.UI.Text;

namespace StemPasswordGenerator.Views;

public sealed class PasswordStrengthLabelFontWeightConverter : IValueConverter
{
    private static readonly FontWeight SemiBold = new() { Weight = 600 };
    private static readonly FontWeight Normal = new() { Weight = 400 };

    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is PasswordStrength strength &&
            parameter is string label &&
            MatchesStrengthLabel(strength, label))
        {
            return SemiBold;
        }

        return Normal;
    }

    private static bool MatchesStrengthLabel(PasswordStrength strength, string label) => label switch
    {
        "Weak" => strength == PasswordStrength.Weak,
        "Medium" => strength == PasswordStrength.Medium,
        "Strong" => strength == PasswordStrength.Strong,
        "Excellent" => strength == PasswordStrength.Excellent,
        _ => false
    };

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotSupportedException();
    }
}
