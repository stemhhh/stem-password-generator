using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class DecoyVaultSeeder
{
    public static IReadOnlyList<VaultItem> CreateSampleItems(SecretGenerator generator)
    {
        ArgumentNullException.ThrowIfNull(generator);
        var options = PasswordOptions.CreateDefault() with { Length = 20 };
        var now = DateTimeOffset.UtcNow.AddDays(-40);

        return
        [
            Login("Gmail", "https://accounts.google.com", "alex.rivera.84@gmail.com", generator.Generate(options), now.AddDays(-12)),
            Login("Microsoft", "https://login.live.com", "a.rivera@outlook.com", generator.Generate(options), now.AddDays(-9)),
            Login("Netflix", "https://www.netflix.com", "alex.rivera.84@gmail.com", generator.Generate(options), now.AddDays(-6)),
            Login("Amazon", "https://www.amazon.com", "alex.r.shop", generator.Generate(options), now.AddDays(-4)),
            Login("Facebook", "https://www.facebook.com", "alex.rivera.84", generator.Generate(options), now.AddDays(-3)),
            Login("LinkedIn", "https://www.linkedin.com", "alex.rivera", generator.Generate(options), now.AddDays(-1)),
            new VaultItem
            {
                Kind = VaultItemKind.Wifi,
                Title = "HomeNetwork",
                Password = generator.Generate(options),
                WifiSecurity = WifiQr.Wpa,
                CreatedUtc = now,
                ModifiedUtc = now
            }
        ];
    }

    private static VaultItem Login(string title, string url, string username, string password, DateTimeOffset stamp)
    {
        return new VaultItem
        {
            Kind = VaultItemKind.Login,
            Title = title,
            Url = url,
            Username = username,
            Password = password,
            CreatedUtc = stamp,
            ModifiedUtc = stamp
        };
    }
}
