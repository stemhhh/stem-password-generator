namespace StemPasswordGenerator.Services;

/// <summary>
/// Breakpoints in effective pixels (DIPs). Windows display scaling is already
/// applied, so 4K at 200% lays out like 1080p — that keeps text readable.
/// </summary>
public static class FluidLayout
{
    public const double MinCardWidth = 360;
    public const double CompactWidth = 820;
    public const double WideWidth = 1380;
    public const double UltraWidth = 2000;
    public const double ReadableTextWidth = 720;

    public static int CardColumns(double width, double minColumnWidth = MinCardWidth, int maxColumns = 3, double gutter = 16)
    {
        if (double.IsNaN(width) || width <= 0)
        {
            return 1;
        }

        var minWidth = Math.Max(160, minColumnWidth);
        var max = Math.Clamp(maxColumns, 1, 4);
        var gap = Math.Max(0, gutter);
        for (var columns = max; columns >= 2; columns--)
        {
            var needed = columns * minWidth + (columns - 1) * gap;
            if (width + 0.5 >= needed)
            {
                return columns;
            }
        }

        return 1;
    }

    public static int GenerateColumns(double width)
    {
        if (width < CompactWidth)
        {
            return 1;
        }

        return width < WideWidth ? 2 : 3;
    }

    public static bool IsCompactVault(double width) => width < 800;

    public static (double Left, double Top, double Right, double Bottom) PagePadding(double width)
    {
        if (width < CompactWidth)
        {
            return (16, 12, 16, 16);
        }

        if (width < WideWidth)
        {
            return (24, 18, 28, 24);
        }

        if (width < UltraWidth)
        {
            return (32, 22, 36, 28);
        }

        return (40, 28, 48, 36);
    }

    public static double Gutter(double width) =>
        width >= UltraWidth ? 20 : 16;

    public static double HistoryMaxHeight(int generateColumns) => generateColumns switch
    {
        3 => 560,
        2 => 320,
        _ => 220
    };

    public static double NavigationPaneLength(double windowWidth) =>
        windowWidth >= UltraWidth ? 248 : 196;
}
