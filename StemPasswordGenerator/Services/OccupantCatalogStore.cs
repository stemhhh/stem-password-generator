using StemPasswordGenerator.Models;
using Windows.Storage;

namespace StemPasswordGenerator.Services;

internal sealed class OccupantCatalogStore
{
    private const string FileName = "occupants.json";

    public OccupantCatalog Catalog { get; private set; } = new();

    public async Task LoadAsync()
    {
        var folder = ApplicationData.Current.LocalFolder;
        if (await folder.TryGetItemAsync(FileName) is StorageFile file)
        {
            Catalog = OccupantCatalogSerializer.Deserialize(await FileIO.ReadTextAsync(file));
        }
        else
        {
            Catalog = new OccupantCatalog();
        }

        Catalog.Occupants ??= [];
        var dirty = SanitizeCatalog();
        await MigrateLegacyVaultAsync(folder);
        if (dirty)
        {
            await SaveAsync();
        }
    }

    public async Task SaveAsync()
    {
        var folder = ApplicationData.Current.LocalFolder;
        var file = await folder.CreateFileAsync(FileName, CreationCollisionOption.ReplaceExisting);
        await FileIO.WriteTextAsync(file, OccupantCatalogSerializer.Serialize(Catalog));
    }

    public VaultOccupant? Active() =>
        Catalog.Occupants.Find(occupant => occupant.Id == Catalog.ActiveId) ?? Catalog.Occupants.FirstOrDefault();

    public async Task SetActiveAsync(Guid id)
    {
        if (Catalog.ActiveId == id)
        {
            return;
        }

        Catalog.ActiveId = id;
        await SaveAsync();
    }

    public async Task<VaultOccupant> AddAsync(string displayName, bool useLegacyRoot = false)
    {
        if (!OccupantRules.CanAddOccupant(Catalog.Occupants.Count))
        {
            throw new InvalidOperationException("This PC already has the maximum number of people.");
        }

        var id = Guid.NewGuid();
        var occupant = new VaultOccupant
        {
            Id = id,
            DisplayName = OccupantRules.NormalizeName(displayName),
            FolderName = useLegacyRoot ? string.Empty : OccupantRules.FolderName(id)
        };
        Catalog.Occupants.Add(occupant);
        Catalog.ActiveId = occupant.Id;
        await SaveAsync();
        return occupant;
    }

    public async Task RemoveAsync(Guid id)
    {
        Catalog.Occupants.RemoveAll(occupant => occupant.Id == id);
        if (Catalog.ActiveId == id)
        {
            Catalog.ActiveId = Catalog.Occupants.FirstOrDefault()?.Id;
        }

        await SaveAsync();
    }

    public async Task TouchAsync(Guid id)
    {
        var occupant = Catalog.Occupants.Find(item => item.Id == id);
        if (occupant is null)
        {
            return;
        }

        occupant.LastUnlockedUtc = DateTimeOffset.UtcNow;
        Catalog.ActiveId = id;
        await SaveAsync();
    }

    public async Task ClearAsync()
    {
        Catalog = new OccupantCatalog();
        await SaveAsync();
    }

    private async Task MigrateLegacyVaultAsync(StorageFolder folder)
    {
        if (Catalog.Occupants.Count > 0)
        {
            return;
        }

        if (await folder.TryGetItemAsync("vault.spg") is null)
        {
            return;
        }

        Catalog.Occupants.Add(new VaultOccupant
        {
            DisplayName = UiStrings.Get("MyVault"),
            FolderName = string.Empty,
            CreatedUtc = DateTimeOffset.UtcNow
        });
        Catalog.ActiveId = Catalog.Occupants[0].Id;
        await SaveAsync();
    }

    private bool SanitizeCatalog()
    {
        var dirty = false;
        foreach (var occupant in Catalog.Occupants)
        {
            var displayName = OccupantRules.NormalizeName(occupant.DisplayName);
            if (!string.Equals(occupant.DisplayName, displayName, StringComparison.Ordinal))
            {
                occupant.DisplayName = displayName;
                dirty = true;
            }

            var folderName = OccupantRules.SanitizeFolderName(occupant.FolderName, occupant.Id);
            if (!string.Equals(occupant.FolderName, folderName, StringComparison.Ordinal))
            {
                occupant.FolderName = folderName;
                dirty = true;
            }
        }

        if (Catalog.Occupants.Count > OccupantRules.MaximumOccupants)
        {
            Catalog.Occupants = Catalog.Occupants.Take(OccupantRules.MaximumOccupants).ToList();
            dirty = true;
        }

        if (Catalog.ActiveId is Guid activeId && Catalog.Occupants.TrueForAll(occupant => occupant.Id != activeId))
        {
            Catalog.ActiveId = Catalog.Occupants.FirstOrDefault()?.Id;
            dirty = true;
        }

        return dirty;
    }
}
