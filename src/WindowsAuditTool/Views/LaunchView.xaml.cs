using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using WindowsAuditTool.Models;
using WindowsAuditTool.Services;

namespace WindowsAuditTool.Views;

public partial class LaunchView : UserControl
{
    private readonly AppConfig _config;
    private readonly bool _isElevated;
    private readonly bool _scriptFound;

    /// <summary>Raised when the user clicks "Run Audit".</summary>
    public event System.Action<AppConfig>? RunRequested;

    public LaunchView()
    {
        InitializeComponent();

        _config = ConfigService.Load();
        _isElevated = ElevationService.IsElevated();
        _scriptFound = new AuditRunner().FindScript() != null;

        SetupUI();
    }

    private void SetupUI()
    {
        // Customer name
        CustomerNameBox.Text = _config.CustomerName;

        // Elevation status
        if (_isElevated)
        {
            ElevDot.Fill = FindResource("GoodBrush") as SolidColorBrush;
            ElevText.Text = "Running as Administrator";
            ElevText.Foreground = FindResource("GoodBrush") as SolidColorBrush;
            ElevationBanner.Background = new SolidColorBrush(Color.FromArgb(0x1A, 0x05, 0x96, 0x69));
            ElevateButton.Visibility = Visibility.Collapsed;
        }
        else
        {
            ElevDot.Fill = FindResource("WarnBrush") as SolidColorBrush;
            ElevText.Text = "Not running as Administrator - some security checks will be skipped";
            ElevText.Foreground = FindResource("WarnBrush") as SolidColorBrush;
            ElevationBanner.Background = new SolidColorBrush(Color.FromArgb(0x1A, 0xD9, 0x77, 0x06));
            ElevateButton.Visibility = Visibility.Visible;
        }

        // Script status
        if (_scriptFound)
        {
            ScriptStatusText.Text = "Run-Audit.ps1 found";
            ScriptStatusText.Foreground = FindResource("GoodBrush") as SolidColorBrush;
            ScriptStatusBorder.Background = new SolidColorBrush(Color.FromArgb(0x1A, 0x05, 0x96, 0x69));
            RunButton.IsEnabled = true;
        }
        else
        {
            ScriptStatusText.Text = "Run-Audit.ps1 not found - place it next to this executable";
            ScriptStatusText.Foreground = FindResource("BadBrush") as SolidColorBrush;
            ScriptStatusBorder.Background = new SolidColorBrush(Color.FromArgb(0x1A, 0xDC, 0x26, 0x26));
            RunButton.IsEnabled = false;
        }

        // Config file indicator
        if (ConfigService.ConfigFileExists())
        {
            ConfigIndicator.Text = "Settings loaded from config.txt";
            ConfigIndicator.Visibility = Visibility.Visible;
        }
    }

    private void ElevateButton_Click(object sender, RoutedEventArgs e)
    {
        if (ElevationService.RestartElevated())
        {
            Application.Current.Shutdown();
        }
    }

    private void RunButton_Click(object sender, RoutedEventArgs e)
    {
        _config.CustomerName = CustomerNameBox.Text.Trim();
        RunRequested?.Invoke(_config);
    }
}
