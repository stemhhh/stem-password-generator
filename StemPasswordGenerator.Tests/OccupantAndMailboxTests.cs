using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class OccupantAndMailboxTests
{
    [Fact]
    public void Migrate_TurnsPrimaryEmailIntoPersonalProfile()
    {
        var settings = new VaultSettings
        {
            PrimaryEmail = "enmanuel@gmail.com",
            Mailboxes = ["Work"]
        };

        MailboxProfileService.Migrate(settings);

        Assert.Equal(2, settings.Profiles.Count);
        Assert.Contains(settings.Profiles, profile => profile.IsDefault && profile.Email == "enmanuel@gmail.com" && profile.Label == "Personal");
        Assert.Contains(settings.Profiles, profile => profile.Label == "Work");
        Assert.Equal("enmanuel@gmail.com", settings.PrimaryEmail);
    }

    [Fact]
    public void OccupantName_StripsPathCharacters()
    {
        Assert.Equal("Alex", OccupantRules.NormalizeName("  Alex  "));
        Assert.DoesNotContain('\\', OccupantRules.NormalizeName(@"Alex\..\Windows"));
        Assert.Equal("Person", OccupantRules.NormalizeName("   "));
        Assert.False(OccupantRules.CanAddOccupant(OccupantRules.MaximumOccupants));
        Assert.True(OccupantRules.CanAddOccupant(1));
    }

    [Fact]
    public void FolderName_IsGuidOnly()
    {
        var id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        Assert.Equal("occupants\\" + id.ToString("N"), OccupantRules.FolderName(id));
        Assert.DoesNotContain("..", OccupantRules.FolderName(id), StringComparison.Ordinal);
    }

    [Fact]
    public void SharedPcGuidance_WarnsAboutHelloAndVisibleNames()
    {
        UiStrings.SetLanguage(AppLanguage.English);
        Assert.Contains("master password", SharedPcGuidance.NamesAreVisible, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Windows user", SharedPcGuidance.SharedWindowsAccount, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Hello", SharedPcGuidance.HelloCannotTellPeopleApart, StringComparison.Ordinal);
        Assert.Contains("unlocked vault", SharedPcGuidance.MailboxProfilesStayInside, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("forensics", SharedPcGuidance.PanicIsNotForensics, StringComparison.OrdinalIgnoreCase);
        Assert.True(OccupantRules.CanAddMailbox(0));
        Assert.False(OccupantRules.CanAddMailbox(OccupantRules.MaximumMailboxProfiles));
    }

    [Fact]
    public void FolderName_RejectsPathTraversal()
    {
        var id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        Assert.True(OccupantRules.IsSafeFolderName(string.Empty));
        Assert.True(OccupantRules.IsSafeFolderName(OccupantRules.FolderName(id)));
        Assert.True(OccupantRules.IsSafeFolderName(OccupantRules.DecoyFolderName));
        Assert.False(OccupantRules.IsSafeFolderName(@"..\vault"));
        Assert.False(OccupantRules.IsSafeFolderName(@"occupants\not-a-guid"));
        Assert.False(OccupantRules.IsSafeFolderName(@"decoy\extra"));
        Assert.False(OccupantRules.IsSafeFolderName("decoys"));
        Assert.Equal(string.Empty, OccupantRules.SanitizeFolderName("  ", id));
        Assert.Equal(OccupantRules.FolderName(id), OccupantRules.SanitizeFolderName(@"..\Windows", id));
    }

    [Fact]
    public void OccupantCatalog_RoundTripsWithoutIndent()
    {
        var catalog = new OccupantCatalog
        {
            Version = 1,
            ActiveId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            Occupants =
            [
                new VaultOccupant
                {
                    Id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
                    DisplayName = "Enmanuel",
                    FolderName = OccupantRules.FolderName(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
                }
            ]
        };

        var json = OccupantCatalogSerializer.Serialize(catalog);
        Assert.DoesNotContain('\n', json);
        var loaded = OccupantCatalogSerializer.Deserialize(json);
        Assert.Equal(catalog.ActiveId, loaded.ActiveId);
        Assert.Equal("Enmanuel", loaded.Occupants[0].DisplayName);
        Assert.Equal(catalog.Occupants[0].FolderName, loaded.Occupants[0].FolderName);
    }
}
