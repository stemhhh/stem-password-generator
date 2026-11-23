using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public readonly record struct IdenticonPattern(
    int Hue,
    byte BackgroundR,
    byte BackgroundG,
    byte BackgroundB,
    byte ForegroundR,
    byte ForegroundG,
    byte ForegroundB,
    int Cells,
    char Letter);

public static class LocalIdenticon
{
    public const int GridSize = 5;
    private const int UniqueColumns = 3;
    private const int CellBits = GridSize * UniqueColumns;

    public static string SeedFor(VaultItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return SeedFor(item.Kind, item.Url, item.Title);
    }

    public static string SeedFor(string? kind, string? url, string? title)
    {
        var host = SiteMatchService.Host(url);
        if (!string.IsNullOrEmpty(host))
        {
            return host;
        }

        var name = (title ?? string.Empty).Trim().ToLowerInvariant();
        var type = string.IsNullOrWhiteSpace(kind) ? VaultItemKind.Login : kind.Trim().ToLowerInvariant();
        return name.Length == 0 ? type : type + ":" + name;
    }

    public static IdenticonPattern FromSeed(string? seed)
    {
        var normalized = string.IsNullOrWhiteSpace(seed) ? "stem" : seed.Trim().ToLowerInvariant();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        var hue = (hash[0] * 360) / 256;
        var cells = hash[1] | ((hash[2] & 0x7F) << 8);
        if (BitOperations.PopCount((uint)cells) < 4)
        {
            cells |= hash[3] | 0x1249;
        }

        cells &= (1 << CellBits) - 1;
        var (br, bg, bb) = HslToRgb(hue, 0.52, 0.34);
        var (fr, fg, fb) = HslToRgb(hue, 0.62, 0.72);
        return new IdenticonPattern(hue, br, bg, bb, fr, fg, fb, cells, LetterFor(normalized));
    }

    public static bool Cell(int cells, int row, int column)
    {
        if (row < 0 || row >= GridSize || column < 0 || column >= GridSize)
        {
            return false;
        }

        var source = column switch
        {
            3 => 1,
            4 => 0,
            _ => column
        };
        var bit = row * UniqueColumns + source;
        return (cells & (1 << bit)) != 0;
    }

    private static char LetterFor(string seed)
    {
        var start = seed.LastIndexOf(':') + 1;
        for (var i = start; i < seed.Length; i++)
        {
            if (char.IsLetterOrDigit(seed[i]))
            {
                return char.ToUpperInvariant(seed[i]);
            }
        }

        return '#';
    }

    private static (byte R, byte G, byte B) HslToRgb(int hue, double saturation, double lightness)
    {
        hue = ((hue % 360) + 360) % 360;
        var c = (1 - Math.Abs(2 * lightness - 1)) * saturation;
        var x = c * (1 - Math.Abs(hue / 60d % 2 - 1));
        var m = lightness - c / 2;
        var (r, g, b) = hue switch
        {
            < 60 => (c, x, 0d),
            < 120 => (x, c, 0d),
            < 180 => (0d, c, x),
            < 240 => (0d, x, c),
            < 300 => (x, 0d, c),
            _ => (c, 0d, x)
        };

        return ((byte)Math.Round((r + m) * 255), (byte)Math.Round((g + m) * 255), (byte)Math.Round((b + m) * 255));
    }
}
