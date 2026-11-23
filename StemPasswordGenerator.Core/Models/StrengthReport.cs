namespace StemPasswordGenerator.Models;

public sealed record StrengthReport(
    PasswordStrength Strength,
    double EntropyBits,
    string EntropyLabel,
    string CrackTimeLabel,
    string Description);
