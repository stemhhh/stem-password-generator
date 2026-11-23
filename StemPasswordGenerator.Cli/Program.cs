using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    Console.WriteLine("""
        stem-pass — local Stem Password Generator CLI (no servers)

        stem-pass generate [length]
        stem-pass totp <base32-or-otpauth>
        stem-pass alias --email you@gmail.com [--domain alias.example.com] [--site github]
        stem-pass health --vault <file.spgs> --password <share-password>

        health reads an exported share/emergency kit, not the DPAPI-locked live vault.
        """);
    return 0;
}

try
{
    return args[0] switch
    {
        "generate" => Generate(args),
        "totp" => Totp(args),
        "alias" => Alias(args),
        "health" => Health(args),
        _ => Fail($"Unknown command '{args[0]}'.")
    };
}
catch (Exception exception)
{
    return Fail(exception.Message);
}

static int Generate(string[] args)
{
    var length = args.Length > 1 && int.TryParse(args[1], out var parsed) ? parsed : PasswordOptions.DefaultPasswordLength;
    var options = PasswordOptions.CreateDefault() with { Length = length };
    Console.WriteLine(new SecretGenerator().Generate(options));
    return 0;
}

static int Totp(string[] args)
{
    if (args.Length < 2)
    {
        return Fail("Usage: stem-pass totp <secret>");
    }

    var secret = TotpService.TryParseOtpAuth(args[1]) ?? args[1];
    Console.WriteLine(TotpService.GetCode(secret));
    return 0;
}

static int Alias(string[] args)
{
    var email = ReadOption(args, "--email") ?? string.Empty;
    var domain = ReadOption(args, "--domain") ?? string.Empty;
    var site = ReadOption(args, "--site") ?? string.Empty;
    Console.WriteLine(AliasGenerator.Generate(email, domain, site));
    return 0;
}

static int Health(string[] args)
{
    var path = ReadOption(args, "--vault");
    var password = ReadOption(args, "--password");
    if (path is null || password is null)
    {
        return Fail("Usage: stem-pass health --vault <file.spgs> --password <password>");
    }

    var blob = File.ReadAllBytes(path);
    var document = new VaultCryptography().Decrypt(blob, password);
    var findings = VaultHealthService.Analyze(document.Items);
    Console.WriteLine($"{document.Items.Count} items, {findings.Count} alerts");
    foreach (var finding in findings)
    {
        Console.WriteLine($"{finding.Severity,-6} {finding.Title}: {finding.Detail}");
    }

    return 0;
}

static string? ReadOption(string[] args, string name)
{
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] == name)
        {
            return args[i + 1];
        }
    }

    return null;
}

static int Fail(string message)
{
    Console.Error.WriteLine(message);
    return 1;
}
