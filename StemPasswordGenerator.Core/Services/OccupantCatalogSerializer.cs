using System.Text.Json;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class OccupantCatalogSerializer
{
    public static OccupantCatalog Deserialize(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return new OccupantCatalog();
        }

        return JsonSerializer.Deserialize(json, VaultJsonContext.Default.OccupantCatalog)
            ?? new OccupantCatalog();
    }

    public static string Serialize(OccupantCatalog catalog) =>
        JsonSerializer.Serialize(catalog ?? new OccupantCatalog(), VaultJsonContext.Default.OccupantCatalog);
}
