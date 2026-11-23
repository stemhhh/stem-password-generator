namespace StemPasswordGenerator.Models;

public sealed class FolderFilterChoice
{
    public FolderFilterChoice(string key, string label)
    {
        Key = key ?? string.Empty;
        Label = label ?? string.Empty;
    }

    public string Key { get; }

    public string Label { get; }

    public override string ToString() => Label;
}
