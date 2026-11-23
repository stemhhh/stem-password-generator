using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using StemPasswordGenerator.Services;
using Windows.UI;

namespace StemPasswordGenerator.Views;

public sealed class IdenticonStamp : UserControl
{
    public static readonly DependencyProperty SeedProperty = DependencyProperty.Register(
        nameof(Seed),
        typeof(string),
        typeof(IdenticonStamp),
        new PropertyMetadata(string.Empty, OnSeedChanged));

    private readonly Border _frame;
    private readonly Image _image;
    private readonly TextBlock _letter;

    public IdenticonStamp()
    {
        IsTabStop = false;
        IsHitTestVisible = false;
        MinWidth = 32;
        MinHeight = 32;
        _image = new Image
        {
            Stretch = Stretch.Uniform,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            VerticalAlignment = VerticalAlignment.Stretch
        };
        _letter = new TextBlock
        {
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            FontSize = 14,
            Foreground = new SolidColorBrush(Color.FromArgb(240, 255, 255, 255))
        };
        var overlay = new Grid
        {
            Children =
            {
                _image,
                new Ellipse
                {
                    Width = 18,
                    Height = 18,
                    Fill = new SolidColorBrush(Color.FromArgb(120, 0, 0, 0)),
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center,
                    IsHitTestVisible = false
                },
                _letter
            }
        };
        _frame = new Border
        {
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(3),
            Child = overlay
        };
        Content = _frame;
        Paint(string.Empty);
    }

    public string Seed
    {
        get => (string)GetValue(SeedProperty);
        set => SetValue(SeedProperty, value);
    }

    private static void OnSeedChanged(DependencyObject sender, DependencyPropertyChangedEventArgs args)
    {
        if (sender is IdenticonStamp stamp)
        {
            stamp.Paint(args.NewValue as string);
        }
    }

    private void Paint(string? seed)
    {
        var pattern = LocalIdenticon.FromSeed(seed);
        _frame.Background = new SolidColorBrush(IdenticonImageCache.BackgroundOf(pattern));
        _image.Source = IdenticonImageCache.Get(seed);
        _letter.Text = pattern.Letter.ToString();
        AutomationProperties.SetName(this, seed ?? string.Empty);
    }
}
