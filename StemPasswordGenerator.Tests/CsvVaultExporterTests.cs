using System.Text;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class CsvVaultExporterTests
{
    [Fact]
    public void Export_IsAcceptedByTheImporter()
    {
        var items = new List<VaultItem>
        {
            new()
            {
                Kind = VaultItemKind.Login,
                Title = "GitHub",
                Url = "https://github.com",
                Username = "enmanuel",
                Password = "s3cret!",
                TotpSecret = "JBSWY3DPEHPK3PXP",
                Notes = "work",
                Folder = "Work"
            },
            new()
            {
                Kind = VaultItemKind.Card,
                Title = "Visa",
                Cardholder = "Alex Rivera",
                CardNumber = "4111111111111111",
                CardExpiry = "12/28",
                CardCvv = "123"
            },
            new()
            {
                Kind = VaultItemKind.Note,
                Title = "Wi-Fi",
                Notes = "HomeNetwork / guest"
            }
        };

        var exported = CsvVaultExporter.Write(items);
        Assert.True(exported.Success);
        Assert.Equal(3, exported.Written);

        var imported = CsvVaultImporter.Parse(exported.Data);
        Assert.True(imported.Success);
        Assert.Equal("bitwarden", imported.Format);
        Assert.Equal(3, imported.Items.Count);
        Assert.Equal("GitHub", imported.Items[0].Title);
        Assert.Equal("https://github.com", imported.Items[0].Url);
        Assert.Equal("enmanuel", imported.Items[0].Username);
        Assert.Equal("s3cret!", imported.Items[0].Password);
        Assert.Equal("JBSWY3DPEHPK3PXP", imported.Items[0].TotpSecret);
        Assert.Equal("work", imported.Items[0].Notes);
        Assert.Equal("Work", imported.Items[0].Folder);
        Assert.Equal(VaultItemKind.Card, imported.Items[1].Kind);
        Assert.Equal("4111111111111111", imported.Items[1].CardNumber);
        Assert.Equal("12/28", imported.Items[1].CardExpiry);
        Assert.Equal(VaultItemKind.Note, imported.Items[2].Kind);
        Assert.Contains("HomeNetwork", imported.Items[2].Notes, StringComparison.Ordinal);
    }

    [Fact]
    public void Export_KeepsBrowserColumnsChromeCanRead()
    {
        var exported = CsvVaultExporter.Write(
        [
            new VaultItem
            {
                Kind = VaultItemKind.Login,
                Title = "Bank",
                Url = "https://bank.example",
                Username = "enmanuel",
                Password = "hunter2-long"
            }
        ]);

        var text = Encoding.UTF8.GetString(exported.Data);
        Assert.Contains("name,url,username,password", text, StringComparison.Ordinal);
        Assert.Contains("https://bank.example", text, StringComparison.Ordinal);
        Assert.Contains("hunter2-long", text, StringComparison.Ordinal);
        Assert.Contains("login_uri", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Export_QuotesCommaAndNewline()
    {
        var exported = CsvVaultExporter.Write(
        [
            new VaultItem
            {
                Kind = VaultItemKind.Login,
                Title = "App",
                Url = "https://app.example",
                Username = "user",
                Password = "a,b\nc"
            }
        ]);

        var imported = CsvVaultImporter.Parse(exported.Data);
        Assert.True(imported.Success);
        Assert.Equal("a,b\nc", imported.Items[0].Password);
    }

    [Fact]
    public void Export_EmptyVault_FailsClosed()
    {
        var result = CsvVaultExporter.Write([]);
        Assert.False(result.Success);
        Assert.Equal("CsvExportEmpty", result.ErrorKey);
        Assert.Empty(result.Data);
    }

    [Fact]
    public void Export_AliasUsesHideMyEmailAsUsername()
    {
        var exported = CsvVaultExporter.Write(
        [
            new VaultItem
            {
                Kind = VaultItemKind.Alias,
                Title = "Shop",
                Url = "https://shop.example",
                AliasEmail = "hide@alias.example",
                Password = "alias-secret"
            }
        ]);

        var imported = CsvVaultImporter.Parse(exported.Data);
        Assert.True(imported.Success);
        Assert.Equal("hide@alias.example", imported.Items[0].Username);
        Assert.Equal("alias-secret", imported.Items[0].Password);
    }
}
