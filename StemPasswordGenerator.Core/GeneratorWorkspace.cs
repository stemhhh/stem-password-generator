using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public sealed class GeneratorWorkspace
{
    private readonly SecretGenerator _generator = new();
    private readonly PasswordStrengthService _strength = new();
    private readonly List<string> _history = new(8);

    public PasswordOptions Options { get; private set; } = PasswordOptions.CreateDefault();

    public string Secret { get; private set; } = string.Empty;

    public StrengthReport Strength { get; private set; } = new(PasswordStrength.Weak, 0, "0-bit entropy", "Instant", string.Empty);

    public IReadOnlyList<string> History => _history;

    public bool CanGenerate => GeneratorPresets.CanGenerate(Options);

    public void Generate()
    {
        Options = Options.Normalize();
        Secret = CanGenerate ? _generator.Generate(Options) : string.Empty;
        Strength = _strength.Evaluate(Secret, Options);
        Remember(Secret);
    }

    public bool ApplyPreset(string name)
    {
        var preset = GeneratorPresets.TryCreate(name);
        if (preset is null)
        {
            return false;
        }

        Options = preset.Normalize();
        Generate();
        return true;
    }

    public void SetOptions(PasswordOptions options)
    {
        Options = options.Normalize();
        Generate();
    }

    private void Remember(string secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return;
        }

        if (_history.Count > 0 && _history[0] == secret)
        {
            return;
        }

        _history.Insert(0, secret);
        while (_history.Count > 8)
        {
            _history.RemoveAt(_history.Count - 1);
        }
    }
}
