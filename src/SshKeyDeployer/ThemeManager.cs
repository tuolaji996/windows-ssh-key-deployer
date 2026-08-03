using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace SshKeyDeployer;

internal static class ThemeManager
{
    private static readonly IReadOnlyDictionary<string, string> LightPalette =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["WindowBrush"] = "#F5F6F8",
            ["NavigationBrush"] = "#FFFFFF",
            ["SurfaceBrush"] = "#FFFFFF",
            ["SurfaceAltBrush"] = "#F0F2F5",
            ["SurfaceHoverBrush"] = "#E9EDF2",
            ["BorderBrush"] = "#D9DEE5",
            ["TextBrush"] = "#1B2027",
            ["MutedTextBrush"] = "#66717E",
            ["SubtleTextBrush"] = "#7C8794",
            ["InputBrush"] = "#FFFFFF",
            ["AccentBrush"] = "#16845D",
            ["AccentHoverBrush"] = "#106C4B",
            ["AccentForegroundBrush"] = "#FFFFFF",
            ["InfoBrush"] = "#2563C7",
            ["WarningBrush"] = "#A65A00",
            ["WarningSurfaceBrush"] = "#FFF4E5",
            ["DangerBrush"] = "#C73535",
            ["NeutralStatusBrush"] = "#7C8794",
            ["StatusBarBrush"] = "#F9FAFB",
            ["SelectionBrush"] = "#DDEFE8"
        };

    private static readonly IReadOnlyDictionary<string, string> DarkPalette =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["WindowBrush"] = "#171A1F",
            ["NavigationBrush"] = "#111418",
            ["SurfaceBrush"] = "#1E2228",
            ["SurfaceAltBrush"] = "#242A31",
            ["SurfaceHoverBrush"] = "#2A313A",
            ["BorderBrush"] = "#343C46",
            ["TextBrush"] = "#F2F5F7",
            ["MutedTextBrush"] = "#A7B0BA",
            ["SubtleTextBrush"] = "#7F8A96",
            ["InputBrush"] = "#171B20",
            ["AccentBrush"] = "#31C88C",
            ["AccentHoverBrush"] = "#43D69C",
            ["AccentForegroundBrush"] = "#07140F",
            ["InfoBrush"] = "#69A1FF",
            ["WarningBrush"] = "#E5A33D",
            ["WarningSurfaceBrush"] = "#342817",
            ["DangerBrush"] = "#F06B6B",
            ["NeutralStatusBrush"] = "#7F8A96",
            ["StatusBarBrush"] = "#14171B",
            ["SelectionBrush"] = "#203A31"
        };

    public static bool IsDark { get; private set; }

    public static void ApplySystemTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            Apply(key?.GetValue("AppsUseLightTheme") is int value && value == 0);
        }
        catch
        {
            Apply(false);
        }
    }

    public static void Toggle() => Apply(!IsDark);

    private static void Apply(bool dark)
    {
        IsDark = dark;
        var palette = dark ? DarkPalette : LightPalette;
        foreach (var (key, color) in palette)
        {
            Application.Current.Resources[key] =
                new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
        }
    }
}
