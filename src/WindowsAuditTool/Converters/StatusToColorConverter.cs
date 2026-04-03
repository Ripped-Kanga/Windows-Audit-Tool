using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using WindowsAuditTool.Models;

namespace WindowsAuditTool.Converters;

/// <summary>
/// Converts an ActionKind to a SolidColorBrush for display in the progress log.
/// </summary>
public sealed class ActionKindToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is ActionKind kind
            ? kind switch
            {
                ActionKind.Run  => new SolidColorBrush(Color.FromRgb(0x00, 0xBC, 0xD4)),  // Cyan
                ActionKind.Ok   => new SolidColorBrush(Color.FromRgb(0x05, 0x96, 0x69)),  // Green
                ActionKind.Warn => new SolidColorBrush(Color.FromRgb(0xD9, 0x77, 0x06)),  // Yellow/amber
                ActionKind.Bad  => new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26)),  // Red
                ActionKind.Skip => new SolidColorBrush(Color.FromRgb(0x9C, 0x8B, 0x00)),  // Dark yellow
                _               => new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B)),  // Gray
            }
            : new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Converts a boolean (elevated) to a brush color.
/// </summary>
public sealed class ElevationToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is true
            ? new SolidColorBrush(Color.FromRgb(0x05, 0x96, 0x69))  // Green
            : new SolidColorBrush(Color.FromRgb(0xD9, 0x77, 0x06)); // Amber
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
