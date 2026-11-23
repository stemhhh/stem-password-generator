using System.Diagnostics;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class GenerationSpeedTests
{
    private readonly SecretGenerator _generator = new();

    [Fact]
    public void Passwords_1000_CompleteUnderOneSecond()
    {
        var options = PasswordOptions.CreateDefault();
        _generator.Generate(options);

        var timer = Stopwatch.StartNew();
        for (var i = 0; i < 1000; i++)
        {
            var secret = _generator.Generate(options);
            Assert.Equal(options.Length, secret.Length);
        }

        timer.Stop();
        Assert.True(timer.ElapsedMilliseconds < 1000, $"Password generation was too slow: {timer.ElapsedMilliseconds}ms");
    }

    [Fact]
    public void Passphrases_300_CompleteUnderOneSecond()
    {
        var options = PasswordOptions.CreateDefault() with
        {
            Mode = GeneratorMode.Passphrase,
            Length = 6
        };
        _generator.Generate(options);

        var timer = Stopwatch.StartNew();
        for (var i = 0; i < 300; i++)
        {
            Assert.False(string.IsNullOrWhiteSpace(_generator.Generate(options)));
        }

        timer.Stop();
        Assert.True(timer.ElapsedMilliseconds < 1000, $"Passphrase generation was too slow: {timer.ElapsedMilliseconds}ms");
    }

    [Fact]
    public void Pins_1000_CompleteUnder250ms()
    {
        var options = PasswordOptions.CreateDefault() with
        {
            Mode = GeneratorMode.Pin,
            Length = 6
        };

        var timer = Stopwatch.StartNew();
        for (var i = 0; i < 1000; i++)
        {
            Assert.Equal(6, _generator.Generate(options).Length);
        }

        timer.Stop();
        Assert.True(timer.ElapsedMilliseconds < 250, $"PIN generation was too slow: {timer.ElapsedMilliseconds}ms");
    }

    [Fact]
    public void Totp_Codes_AreCheapToRefresh()
    {
        var secret = TotpService.GenerateSecret();
        TotpService.GetCode(secret);

        var timer = Stopwatch.StartNew();
        for (var i = 0; i < 200; i++)
        {
            Assert.Equal(6, TotpService.GetCode(secret).Length);
        }

        timer.Stop();
        Assert.True(timer.ElapsedMilliseconds < 200, $"TOTP refresh was too slow: {timer.ElapsedMilliseconds}ms");
    }

    [Fact]
    public void Passwords_AreNotRepeatedInABurst()
    {
        var options = PasswordOptions.CreateDefault();
        var secrets = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < 80; i++)
        {
            Assert.True(secrets.Add(_generator.Generate(options)));
        }
    }

    [Fact]
    public void HealthScan_200Logins_CompletesUnder100ms()
    {
        var items = new List<VaultItem>(200);
        for (var i = 0; i < 200; i++)
        {
            items.Add(new VaultItem
            {
                Title = $"Login {i}",
                Password = i % 15 == 0 ? "shared-password-12" : $"unique-password-{i:000}",
                Kind = VaultItemKind.Login
            });
        }

        VaultHealthService.Analyze(items);

        var timer = Stopwatch.StartNew();
        var findings = VaultHealthService.Analyze(items);
        timer.Stop();

        Assert.NotEmpty(findings);
        Assert.True(timer.ElapsedMilliseconds < 100, $"Health scan was too slow: {timer.ElapsedMilliseconds}ms");
    }

    [Fact]
    public void Checker_500Secrets_CompleteUnder250ms()
    {
        SecretCheckService.Analyze("warmup-vK7!mQ2pL9");

        var samples = new[]
        {
            "1234",
            "password",
            "i love you",
            "vK7!mQ2pL9#zR4wY",
            "48291736",
            "maple-harbor-quartz-velvet"
        };

        var timer = Stopwatch.StartNew();
        for (var i = 0; i < 500; i++)
        {
            var report = SecretCheckService.Analyze(samples[i % samples.Length]);
            Assert.True(report.EntropyBits > 0);
        }

        timer.Stop();
        Assert.True(timer.ElapsedMilliseconds < 80, $"Password check was too slow: {timer.ElapsedMilliseconds}ms");
    }
}
