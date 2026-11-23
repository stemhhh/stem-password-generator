using Microsoft.UI.Xaml.Data;

namespace StemPasswordGenerator.Views;

public sealed class StringToOpacityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        return value is string text && !string.IsNullOrWhiteSpace(text) ? 1d : 0d;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotSupportedException();
    }
}
