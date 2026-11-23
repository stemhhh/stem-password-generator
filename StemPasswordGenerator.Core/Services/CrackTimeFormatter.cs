using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class CrackTimeFormatter
{
    private const double GuessesPerSecond = 1_000_000_000_000d;

    public static string Label(double entropyBits)
    {
        var seconds = Math.Pow(2, Math.Max(entropyBits, 0)) / GuessesPerSecond / 2d;
        if (seconds < 1)
        {
            return UiStrings.Get("CrackInstant");
        }

        if (seconds < 60)
        {
            return UiStrings.Format("CrackSeconds", seconds.ToString("0"));
        }

        if (seconds < 3_600)
        {
            return UiStrings.Format("CrackMinutes", (seconds / 60).ToString("0"));
        }

        if (seconds < 86_400)
        {
            return UiStrings.Format("CrackHours", (seconds / 3_600).ToString("0"));
        }

        if (seconds < 31_536_000)
        {
            return UiStrings.Format("CrackDays", (seconds / 86_400).ToString("0"));
        }

        if (seconds < 3_153_600_000)
        {
            return UiStrings.Format("CrackYears", (seconds / 31_536_000).ToString("0"));
        }

        return UiStrings.Get("CrackCenturies");
    }
}
