using System.Runtime.InteropServices.WindowsRuntime;
using Microsoft.UI.Xaml.Media.Imaging;
using StemPasswordGenerator.Services;
using Windows.UI;

namespace StemPasswordGenerator.Views;

internal static class IdenticonImageCache
{
    private const int CellPixels = 8;
    private const int Gap = 1;
    private const int MaxEntries = 192;

    private static readonly Dictionary<string, WriteableBitmap> Images = new(StringComparer.Ordinal);
    private static readonly LinkedList<string> Order = new();

    public static int PixelSize =>
        LocalIdenticon.GridSize * CellPixels + (LocalIdenticon.GridSize - 1) * Gap;

    public static WriteableBitmap Get(string? seed)
    {
        var key = string.IsNullOrWhiteSpace(seed) ? "stem" : seed.Trim().ToLowerInvariant();
        if (Images.TryGetValue(key, out var cached))
        {
            Order.Remove(key);
            Order.AddLast(key);
            return cached;
        }

        var bitmap = Render(LocalIdenticon.FromSeed(key));
        Images[key] = bitmap;
        Order.AddLast(key);
        while (Images.Count > MaxEntries && Order.First is not null)
        {
            var oldest = Order.First.Value;
            Order.RemoveFirst();
            Images.Remove(oldest);
        }

        return bitmap;
    }

    private static WriteableBitmap Render(IdenticonPattern pattern)
    {
        var size = PixelSize;
        var bitmap = new WriteableBitmap(size, size);
        var pixels = new byte[size * size * 4];
        var background = Pack(pattern.BackgroundR, pattern.BackgroundG, pattern.BackgroundB);
        var foreground = Pack(pattern.ForegroundR, pattern.ForegroundG, pattern.ForegroundB);

        for (var row = 0; row < LocalIdenticon.GridSize; row++)
        {
            for (var column = 0; column < LocalIdenticon.GridSize; column++)
            {
                var color = LocalIdenticon.Cell(pattern.Cells, row, column) ? foreground : background;
                var x0 = column * (CellPixels + Gap);
                var y0 = row * (CellPixels + Gap);
                Fill(pixels, size, x0, y0, CellPixels, CellPixels, color);
            }
        }

        using (var stream = bitmap.PixelBuffer.AsStream())
        {
            stream.Write(pixels, 0, pixels.Length);
        }

        bitmap.Invalidate();
        return bitmap;
    }

    private static void Fill(byte[] pixels, int stride, int x0, int y0, int width, int height, (byte B, byte G, byte R, byte A) color)
    {
        for (var y = 0; y < height; y++)
        {
            var row = (y0 + y) * stride * 4;
            for (var x = 0; x < width; x++)
            {
                var i = row + ((x0 + x) * 4);
                pixels[i] = color.B;
                pixels[i + 1] = color.G;
                pixels[i + 2] = color.R;
                pixels[i + 3] = color.A;
            }
        }
    }

    private static (byte B, byte G, byte R, byte A) Pack(byte r, byte g, byte b) => (b, g, r, 255);

    public static Color BackgroundOf(IdenticonPattern pattern) =>
        Color.FromArgb(255, pattern.BackgroundR, pattern.BackgroundG, pattern.BackgroundB);
}
