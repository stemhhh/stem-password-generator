using System.Text;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class CsvVaultImporterTests
{
    [Fact]
    public void ChromeCsv_ImportsLogins()
    {
        var csv = """
            name,url,username,password
            GitHub,https://github.com,enmanuel,s3cret!
            Netflix,https://www.netflix.com,enmanuel@mail.com,old-netflix
            """;

        var result = CsvVaultImporter.Parse(Encoding.UTF8.GetBytes(csv));

        Assert.True(result.Success);
        Assert.Equal("chromium", result.Format);
        Assert.Equal(2, result.Items.Count);
        Assert.Equal("GitHub", result.Items[0].Title);
        Assert.Equal("https://github.com", result.Items[0].Url);
        Assert.Equal("enmanuel", result.Items[0].Username);
        Assert.Equal("s3cret!", result.Items[0].Password);
        Assert.Equal("Netflix", result.Items[1].Title);
    }

    [Fact]
    public void EdgeCsv_WithNotes_IsChromium()
    {
        var csv = """
            name,url,username,password,note
            Bank,https://bank.example,enmanuel,hunter2-long,"routing 001"
            """;

        var result = CsvVaultImporter.Parse(Encoding.UTF8.GetBytes(csv));

        Assert.True(result.Success);
        Assert.Equal("chromium", result.Format);
        Assert.Equal("routing 001", result.Items[0].Notes);
    }

    [Fact]
    public void QuotedPassword_KeepsCommaAndNewline()
    {
        var csv = "name,url,username,password\r\nApp,https://app.example,user,\"a,b\nc\"\r\n";

        var result = CsvVaultImporter.Parse(Encoding.UTF8.GetBytes(csv));

        Assert.True(result.Success);
        Assert.Equal("a,b\nc", result.Items[0].Password);
    }

    [Fact]
    public void BitwardenCsv_ImportsLoginTotpNoteAndCard()
    {
            var csv = string.Join("\n",
            [
                "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp,card_cardholderName,card_number,card_expMonth,card_expYear,card_code",
                "Work,0,login,GitHub,, ,0,https://github.com,enmanuel,s3cret!,JBSWY3DPEHPK3PXP,,,,,",
                ",0,note,Wi-Fi,HomeNetwork / guest,,0,,,,,,,,,",
                ",0,card,Visa,, ,0,,,,,Alex Rivera,4111111111111111,12,2028,123"
            ]);

        var result = CsvVaultImporter.Parse(Encoding.UTF8.GetBytes(csv));

        Assert.True(result.Success);
        Assert.Equal("bitwarden", result.Format);
        Assert.Equal(3, result.Items.Count);
        Assert.Equal(VaultItemKind.Login, result.Items[0].Kind);
        Assert.Equal("JBSWY3DPEHPK3PXP", result.Items[0].TotpSecret);
        Assert.Equal("Work", result.Items[0].Folder);
        Assert.Equal(VaultItemKind.Note, result.Items[1].Kind);
        Assert.Contains("HomeNetwork", result.Items[1].Notes, StringComparison.Ordinal);
        Assert.Equal(VaultItemKind.Card, result.Items[2].Kind);
        Assert.Equal("4111111111111111", result.Items[2].CardNumber);
        Assert.Equal("12/28", result.Items[2].CardExpiry);
        Assert.Equal("123", result.Items[2].CardCvv);
    }

    [Fact]
    public void Utf8Bom_DoesNotBreakHeaders()
    {
        var csv = "name,url,username,password\nGitHub,https://github.com,enmanuel,s3cret!\n";
        var data = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(csv)).ToArray();

        var result = CsvVaultImporter.Parse(data);

        Assert.True(result.Success);
        Assert.Equal("GitHub", result.Items[0].Title);
    }

    [Fact]
    public void DuplicateInFile_IsSkipped()
    {
        var csv = """
            name,url,username,password
            GitHub,https://github.com,enmanuel,one
            GitHub,https://www.github.com,enmanuel,two
            """;

        var result = CsvVaultImporter.Parse(Encoding.UTF8.GetBytes(csv));

        Assert.True(result.Success);
        Assert.Single(result.Items);
        Assert.Equal(1, result.Skipped);
        Assert.Equal("one", result.Items[0].Password);
    }

    [Fact]
    public void ExistingVaultDuplicate_IsDetected()
    {
        var existing = new List<VaultItem>
        {
            new() { Title = "GitHub", Url = "https://github.com", Username = "enmanuel", Password = "old", Kind = VaultItemKind.Login }
        };
        var incoming = new VaultItem
        {
            Title = "Work",
            Url = "https://www.github.com",
            Username = "enmanuel",
            Password = "new",
            Kind = VaultItemKind.Login
        };

        Assert.True(CsvVaultImporter.IsDuplicate(incoming, existing));
    }

    [Fact]
    public void UnknownFormat_FailsClosed()
    {
        var result = CsvVaultImporter.Parse("not,a,password,file\n1,2,3,4\n"u8.ToArray());
        Assert.False(result.Success);
        Assert.Equal("CsvUnrecognized", result.ErrorKey);
    }

    [Fact]
    public void EmptyAndHuge_FailClosed()
    {
        Assert.Equal("CsvEmpty", CsvVaultImporter.Parse([])!.ErrorKey);
        Assert.Equal("CsvTooLarge", CsvVaultImporter.Parse(new byte[CsvVaultImporter.MaximumBytes + 1]).ErrorKey);
        Assert.Equal("CsvEmpty", CsvVaultImporter.Parse("name,url,username,password\n"u8.ToArray()).ErrorKey);
    }

    [Fact]
    public void MissingPassword_IsSkipped()
    {
        var csv = """
            name,url,username,password
            Empty,https://example.com,user,
            Keep,https://keep.example,user,present-secret
            """;

        var result = CsvVaultImporter.Parse(Encoding.UTF8.GetBytes(csv));

        Assert.True(result.Success);
        Assert.Single(result.Items);
        Assert.Equal("Keep", result.Items[0].Title);
        Assert.Equal(1, result.Skipped);
    }

    [Fact]
    public void SemicolonCsv_IsAccepted()
    {
        var csv = "name;url;username;password\nGitHub;https://github.com;enmanuel;s3cret!\n";

        var result = CsvVaultImporter.Parse(Encoding.UTF8.GetBytes(csv));

        Assert.True(result.Success);
        Assert.Equal("s3cret!", result.Items[0].Password);
    }

    [Fact]
    public void FirefoxCsv_ImportsLogins()
    {
        var csv = """
            "url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"
            "https://github.com","enmanuel","fx-secret","","https://github.com","{11111111-1111-1111-1111-111111111111}","1","2","3"
            """;

        var result = CsvVaultImporter.Parse(Encoding.UTF8.GetBytes(csv));

        Assert.True(result.Success);
        Assert.Equal("firefox", result.Format);
        Assert.Equal("https://github.com", result.Items[0].Url);
        Assert.Equal("enmanuel", result.Items[0].Username);
        Assert.Equal("fx-secret", result.Items[0].Password);
    }

    [Fact]
    public void OnePasswordCsv_ImportsLoginAndTotp()
    {
        var csv = """
            Title,Website,Username,Password,Notes,One-time password
            GitHub,https://github.com,enmanuel,op-secret,work,otpauth://totp/GitHub:enmanuel?secret=JBSWY3DPEHPK3PXP
            """;

        var result = CsvVaultImporter.Parse(Encoding.UTF8.GetBytes(csv));

        Assert.True(result.Success);
        Assert.Equal("onepassword", result.Format);
        Assert.Equal("GitHub", result.Items[0].Title);
        Assert.Equal("https://github.com", result.Items[0].Url);
        Assert.Equal("op-secret", result.Items[0].Password);
        Assert.Equal("JBSWY3DPEHPK3PXP", result.Items[0].TotpSecret);
        Assert.Equal("work", result.Items[0].Notes);
    }

    [Fact]
    public void KeePassCsv_ImportsClassicAndXc()
    {
        var classic = """
            Account,Login Name,Password,Web Site,Comments
            Mail,enmanuel,kp-secret,https://mail.example,keep this
            """;
        var xc = """
            Group,Title,Username,Password,URL,Notes,TOTP,Icon,Last Modified,Created
            Root/Email,Mail,enmanuel,xc-secret,https://mail.example,from xc,JBSWY3DPEHPK3PXP,0,,
            """;

        var classicResult = CsvVaultImporter.Parse(Encoding.UTF8.GetBytes(classic));
        var xcResult = CsvVaultImporter.Parse(Encoding.UTF8.GetBytes(xc));

        Assert.True(classicResult.Success);
        Assert.Equal("keepass", classicResult.Format);
        Assert.Equal("Mail", classicResult.Items[0].Title);
        Assert.Equal("enmanuel", classicResult.Items[0].Username);
        Assert.Equal("https://mail.example", classicResult.Items[0].Url);
        Assert.Equal("keep this", classicResult.Items[0].Notes);

        Assert.True(xcResult.Success);
        Assert.Equal("keepass", xcResult.Format);
        Assert.Equal("xc-secret", xcResult.Items[0].Password);
        Assert.Equal("JBSWY3DPEHPK3PXP", xcResult.Items[0].TotpSecret);
        Assert.Equal("Root Email", xcResult.Items[0].Folder);
    }
}
