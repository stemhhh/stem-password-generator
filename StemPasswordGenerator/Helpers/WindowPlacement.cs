using System.Runtime.InteropServices;
using Microsoft.UI.Windowing;
using Windows.Graphics;

namespace StemPasswordGenerator.Helpers;

internal static class WindowPlacement
{
    public const double IdealWidthDip = 1280;
    public const double IdealHeightDip = 860;
    public const double MinimumWidthDip = 640;
    public const double MinimumHeightDip = 600;
    public const double WorkAreaMarginDip = 24;

    public static double GetScale(IntPtr windowHandle)
    {
        var dpi = GetDpiForWindow(windowHandle);
        return dpi == 0 ? 1d : dpi / 96d;
    }

    public static int DipToPixels(double dip, double scale)
    {
        return Math.Max(1, (int)Math.Round(dip * scale, MidpointRounding.AwayFromZero));
    }

    public static RectInt32 FitInitial(IntPtr windowHandle, DisplayArea displayArea, double? scale = null)
    {
        var workArea = displayArea.WorkArea;
        var resolvedScale = scale is > 0 ? scale.Value : GetScale(windowHandle);
        var requestedWidth = DipToPixels(IdealWidthDip, resolvedScale);
        var requestedHeight = DipToPixels(IdealHeightDip, resolvedScale);
        return FitToWorkArea(
            workArea,
            requestedWidth,
            requestedHeight,
            DipToPixels(MinimumWidthDip, resolvedScale),
            DipToPixels(MinimumHeightDip, resolvedScale),
            DipToPixels(WorkAreaMarginDip, resolvedScale));
    }

    public static RectInt32? FitIfOutside(AppWindow appWindow, DisplayArea displayArea)
    {
        var work = displayArea.WorkArea;
        var position = appWindow.Position;
        var size = appWindow.Size;
        var intersects =
            position.X < work.X + work.Width
            && position.X + size.Width > work.X
            && position.Y < work.Y + work.Height
            && position.Y + size.Height > work.Y;

        return intersects
            ? null
            : FitToWorkArea(
                work,
                size.Width,
                size.Height,
                1,
                1,
                0,
                position.X,
                position.Y);
    }

    private static RectInt32 FitToWorkArea(
        RectInt32 workArea,
        int requestedWidth,
        int requestedHeight,
        int minimumWidth,
        int minimumHeight,
        int margin,
        int? requestedX = null,
        int? requestedY = null)
    {
        var maxWidth = Math.Max(1, workArea.Width - Math.Min(margin, Math.Max(0, workArea.Width - 1)));
        var maxHeight = Math.Max(1, workArea.Height - Math.Min(margin, Math.Max(0, workArea.Height - 1)));

        var width = Math.Min(Math.Max(requestedWidth, 1), maxWidth);
        var height = Math.Min(Math.Max(requestedHeight, 1), maxHeight);

        if (maxWidth >= minimumWidth)
        {
            width = Math.Max(width, minimumWidth);
        }

        if (maxHeight >= minimumHeight)
        {
            height = Math.Max(height, minimumHeight);
        }

        width = Math.Min(width, workArea.Width);
        height = Math.Min(height, workArea.Height);

        var maxX = workArea.X + Math.Max(0, workArea.Width - width);
        var maxY = workArea.Y + Math.Max(0, workArea.Height - height);
        var x = requestedX ?? workArea.X + Math.Max(0, (workArea.Width - width) / 2);
        var y = requestedY ?? workArea.Y + Math.Max(0, (workArea.Height - height) / 2);

        return new RectInt32(
            Math.Clamp(x, workArea.X, maxX),
            Math.Clamp(y, workArea.Y, maxY),
            width,
            height);
    }

    public static RectInt32 ScaleKeepingOrigin(
        AppWindow appWindow,
        DisplayArea displayArea,
        double fromScale,
        double toScale)
    {
        var factor = fromScale > 0 ? toScale / fromScale : 1d;
        var size = appWindow.Size;
        var position = appWindow.Position;
        var width = Math.Max(1, (int)Math.Round(size.Width * factor, MidpointRounding.AwayFromZero));
        var height = Math.Max(1, (int)Math.Round(size.Height * factor, MidpointRounding.AwayFromZero));
        return FitToWorkArea(
            displayArea.WorkArea,
            width,
            height,
            DipToPixels(MinimumWidthDip, toScale),
            DipToPixels(MinimumHeightDip, toScale),
            DipToPixels(WorkAreaMarginDip, toScale),
            position.X,
            position.Y);
    }

    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hwnd);
}
