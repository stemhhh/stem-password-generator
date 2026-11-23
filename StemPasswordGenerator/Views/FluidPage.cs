using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using StemPasswordGenerator.Services;

namespace StemPasswordGenerator.Views;

public static class FluidPage
{
    public static readonly DependencyProperty EnableProperty =
        DependencyProperty.RegisterAttached(
            "Enable",
            typeof(bool),
            typeof(FluidPage),
            new PropertyMetadata(false, OnEnableChanged));

    public static bool GetEnable(DependencyObject obj) => (bool)obj.GetValue(EnableProperty);

    public static void SetEnable(DependencyObject obj, bool value) => obj.SetValue(EnableProperty, value);

    private static void OnEnableChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not FrameworkElement element)
        {
            return;
        }

        element.SizeChanged -= OnSizeChanged;
        if (e.NewValue is true)
        {
            element.SizeChanged += OnSizeChanged;
            Apply(element, element.ActualWidth);
        }
    }

    private static void OnSizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (Math.Abs(e.NewSize.Width - e.PreviousSize.Width) < 0.5)
        {
            return;
        }

        if (sender is FrameworkElement element)
        {
            Apply(element, e.NewSize.Width);
        }
    }

    private static void Apply(FrameworkElement element, double width)
    {
        var pad = FluidLayout.PagePadding(width);
        var thickness = new Thickness(pad.Left, pad.Top, pad.Right, pad.Bottom);
        if (element is Control control)
        {
            SetPadding(control, thickness);
        }
        else if (element is Grid grid)
        {
            SetPadding(grid, thickness);
        }
        else if (element is Border border)
        {
            SetPadding(border, thickness);
        }
        else if (element is StackPanel stack)
        {
            SetPadding(stack, thickness);
        }
    }

    private static void SetPadding(Control control, Thickness thickness)
    {
        if (SamePadding(control.Padding, thickness))
        {
            return;
        }

        control.Padding = thickness;
    }

    private static void SetPadding(Grid grid, Thickness thickness)
    {
        if (SamePadding(grid.Padding, thickness))
        {
            return;
        }

        grid.Padding = thickness;
    }

    private static void SetPadding(Border border, Thickness thickness)
    {
        if (SamePadding(border.Padding, thickness))
        {
            return;
        }

        border.Padding = thickness;
    }

    private static void SetPadding(StackPanel stack, Thickness thickness)
    {
        if (SamePadding(stack.Padding, thickness))
        {
            return;
        }

        stack.Padding = thickness;
    }

    private static bool SamePadding(Thickness left, Thickness right) =>
        Math.Abs(left.Left - right.Left) < 0.5
        && Math.Abs(left.Top - right.Top) < 0.5
        && Math.Abs(left.Right - right.Right) < 0.5
        && Math.Abs(left.Bottom - right.Bottom) < 0.5;
}
