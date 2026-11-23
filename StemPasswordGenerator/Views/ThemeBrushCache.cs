using Microsoft.UI.Xaml;

namespace StemPasswordGenerator.Views;

internal static class ThemeBrushCache
{
    private static readonly Dictionary<string, object> Brushes = new(StringComparer.Ordinal);

    public static object Get(string key)
    {
        if (Brushes.TryGetValue(key, out var cached))
        {
            return cached;
        }

        var value = Application.Current.Resources.TryGetValue(key, out var brush)
            ? brush
            : DependencyProperty.UnsetValue;
        Brushes[key] = value;
        return value;
    }

    public static void Clear() => Brushes.Clear();
}
