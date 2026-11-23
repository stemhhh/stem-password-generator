using System.ComponentModel;
using System.Runtime.CompilerServices;
using Microsoft.UI.Xaml.Media.Imaging;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;

namespace StemPasswordGenerator.ViewModels;

public sealed class MediaGalleryRow : INotifyPropertyChanged
{
    private BitmapImage? _thumbnail;

    public event PropertyChangedEventHandler? PropertyChanged;

    public Guid Id { get; init; }

    public string Title { get; init; } = string.Empty;

    public string SizeLabel { get; init; } = string.Empty;

    public string DateLabel { get; init; } = string.Empty;

    public string TagLabel { get; init; } = string.Empty;

    public string TypeLabel { get; init; } = string.Empty;

    public string Glyph { get; init; } = "\uE8A5";

    public string Category { get; init; } = MediaCategory.File;

    public string TagOrUnfiled =>
        string.IsNullOrWhiteSpace(TagLabel) ? UiStrings.Get("FolderUnfiled") : TagLabel;

    public BitmapImage? Thumbnail
    {
        get => _thumbnail;
        set
        {
            if (ReferenceEquals(_thumbnail, value))
            {
                return;
            }

            _thumbnail = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(HasThumbnail));
        }
    }

    public bool HasThumbnail => _thumbnail is not null;

    public static MediaGalleryRow From(MediaEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var list = VaultListItem.From(entry);
        return new MediaGalleryRow
        {
            Id = entry.Id,
            Title = list.Title,
            SizeLabel = list.Username,
            DateLabel = ItemUsage.FormatLocalDateTime(entry.CreatedUtc),
            TagLabel = VaultOrganizer.Normalize(entry.Folder),
            TypeLabel = list.KindLabel,
            Glyph = GlyphFor(entry.Category),
            Category = entry.Category
        };
    }

    public static string GlyphFor(string category) => category switch
    {
        MediaCategory.Photo => "\uE91B",
        MediaCategory.Video => "\uE714",
        MediaCategory.Audio => "\uE8D6",
        _ => "\uE8A5"
    };

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
