using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class PendingVaultHoldTests
{
    [Fact]
    public void Hold_DoesNotPublishItemsUntilTake()
    {
        var live = new VaultDocument();
        using var hold = new PendingVaultHold(DocumentWithSecret("hidden-password"));

        Assert.True(hold.HasPayload);
        Assert.Empty(live.Items);
        Assert.False(VaultLooksUnlocked(live, pending: true));
        Assert.False(CanAutofill(live, pending: true));
        Assert.False(CanMedia(live, pending: true));

        live = hold.Take();
        Assert.False(hold.HasPayload);
        Assert.Equal("hidden-password", live.Items[0].Password);
        Assert.True(VaultLooksUnlocked(live, pending: false));
        Assert.Throws<InvalidOperationException>(() => hold.Take());
    }

    [Fact]
    public void Dispose_WipesSecretsAndBlocksTake()
    {
        var document = DocumentWithSecret("wipe-me");
        var item = document.Items[0];
        var hold = new PendingVaultHold(document);
        hold.Dispose();

        Assert.False(hold.HasPayload);
        Assert.Equal(string.Empty, item.Password);
        Assert.Throws<InvalidOperationException>(() => hold.Take());
    }

    private static VaultDocument DocumentWithSecret(string password) =>
        new()
        {
            Items =
            {
                new VaultItem
                {
                    Title = "Mail",
                    Password = password,
                    Kind = VaultItemKind.Login
                }
            }
        };

    private static bool VaultLooksUnlocked(VaultDocument live, bool pending) =>
        !pending && live.Items.Count > 0;

    private static bool CanAutofill(VaultDocument live, bool pending) => VaultLooksUnlocked(live, pending);

    private static bool CanMedia(VaultDocument live, bool pending) => VaultLooksUnlocked(live, pending);
}
