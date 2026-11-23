using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using StemPasswordGenerator.Services;
using Windows.Foundation;

namespace StemPasswordGenerator.Views;

public sealed class FluidCardPanel : Panel
{
    public static readonly DependencyProperty MinColumnWidthProperty =
        DependencyProperty.Register(nameof(MinColumnWidth), typeof(double), typeof(FluidCardPanel),
            new PropertyMetadata(FluidLayout.MinCardWidth, OnLayoutPropertyChanged));

    public static readonly DependencyProperty MaxColumnsProperty =
        DependencyProperty.Register(nameof(MaxColumns), typeof(int), typeof(FluidCardPanel),
            new PropertyMetadata(3, OnLayoutPropertyChanged));

    public static readonly DependencyProperty ColumnSpacingProperty =
        DependencyProperty.Register(nameof(ColumnSpacing), typeof(double), typeof(FluidCardPanel),
            new PropertyMetadata(16d, OnLayoutPropertyChanged));

    public static readonly DependencyProperty RowSpacingProperty =
        DependencyProperty.Register(nameof(RowSpacing), typeof(double), typeof(FluidCardPanel),
            new PropertyMetadata(16d, OnLayoutPropertyChanged));

    private readonly List<UIElement> _visible = [];
    private readonly List<double> _rowHeights = [];
    private readonly List<double> _rowTops = [];

    public double MinColumnWidth
    {
        get => (double)GetValue(MinColumnWidthProperty);
        set => SetValue(MinColumnWidthProperty, value);
    }

    public int MaxColumns
    {
        get => (int)GetValue(MaxColumnsProperty);
        set => SetValue(MaxColumnsProperty, value);
    }

    public double ColumnSpacing
    {
        get => (double)GetValue(ColumnSpacingProperty);
        set => SetValue(ColumnSpacingProperty, value);
    }

    public double RowSpacing
    {
        get => (double)GetValue(RowSpacingProperty);
        set => SetValue(RowSpacingProperty, value);
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        CollectVisible();
        if (_visible.Count == 0)
        {
            return new Size(0, 0);
        }

        var width = double.IsNaN(availableSize.Width) || double.IsInfinity(availableSize.Width) || availableSize.Width <= 0
            ? MinColumnWidth
            : availableSize.Width;
        var columns = FluidLayout.CardColumns(width, MinColumnWidth, MaxColumns, ColumnSpacing);
        var columnWidth = ColumnWidth(width, columns);
        _rowHeights.Clear();
        var column = 0;
        var row = 0;
        foreach (var child in _visible)
        {
            child.Measure(new Size(columnWidth, double.PositiveInfinity));
            if (_rowHeights.Count <= row)
            {
                _rowHeights.Add(0);
            }

            _rowHeights[row] = Math.Max(_rowHeights[row], child.DesiredSize.Height);
            column++;
            if (column >= columns)
            {
                column = 0;
                row++;
            }
        }

        var height = 0d;
        for (var i = 0; i < _rowHeights.Count; i++)
        {
            height += _rowHeights[i];
            if (i > 0)
            {
                height += RowSpacing;
            }
        }

        return new Size(width, height);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        if (_visible.Count == 0)
        {
            CollectVisible();
        }

        if (_visible.Count == 0)
        {
            return finalSize;
        }

        var columns = Math.Max(1, FluidLayout.CardColumns(finalSize.Width, MinColumnWidth, MaxColumns, ColumnSpacing));
        var columnWidth = ColumnWidth(finalSize.Width, columns);
        _rowHeights.Clear();
        for (var i = 0; i < _visible.Count; i++)
        {
            var row = i / columns;
            if (_rowHeights.Count <= row)
            {
                _rowHeights.Add(0);
            }

            _rowHeights[row] = Math.Max(_rowHeights[row], _visible[i].DesiredSize.Height);
        }

        _rowTops.Clear();
        var top = 0d;
        for (var r = 0; r < _rowHeights.Count; r++)
        {
            _rowTops.Add(top);
            top += _rowHeights[r] + RowSpacing;
        }

        for (var i = 0; i < _visible.Count; i++)
        {
            var row = i / columns;
            var column = i % columns;
            var x = column * (columnWidth + ColumnSpacing);
            _visible[i].Arrange(new Rect(x, _rowTops[row], columnWidth, _rowHeights[row]));
        }

        return finalSize;
    }

    private double ColumnWidth(double totalWidth, int columns)
    {
        var gaps = Math.Max(0, columns - 1) * ColumnSpacing;
        return Math.Max(0, (totalWidth - gaps) / columns);
    }

    private void CollectVisible()
    {
        _visible.Clear();
        foreach (var child in Children)
        {
            if (child.Visibility != Visibility.Collapsed)
            {
                _visible.Add(child);
            }
        }
    }

    private static void OnLayoutPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        (d as FluidCardPanel)?.InvalidateMeasure();
    }
}
