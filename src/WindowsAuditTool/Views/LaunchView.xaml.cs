using System;
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
    private UpdateInfo? _updateInfo;

    /// <summary>Raised when the user clicks "Run Audit".</summary>
    public event Action<AppConfig>? RunRequested;

    public LaunchView()
    {
        InitializeComponent();

        _config = ConfigService.Load();
        _isElevated = ElevationService.IsElevated();
        _scriptFound = new AuditRunner().FindScript() != null;

        SetupUI();
        CheckForUpdateAsync();
    }

    private void SetupUI()
    {
        // Version display
        VersionText.Text = $"GUI v{UpdateService.GetCurrentVersion()}";

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
            ScriptStatusText.Text = "Run-Audit.ps1 not found";
            ScriptStatusText.Foreground = FindResource("BadBrush") as SolidColorBrush;
            ScriptStatusBorder.Background = new SolidColorBrush(Color.FromArgb(0x1A, 0xDC, 0x26, 0x26));
            DownloadScriptButton.Visibility = Visibility.Visible;
            RunButton.IsEnabled = false;
        }

        // Config file indicator
        if (ConfigService.ConfigFileExists())
        {
            ConfigIndicator.Text = "Settings loaded from config.txt";
            ConfigIndicator.Visibility = Visibility.Visible;
        }
    }

    private async void CheckForUpdateAsync()
    {
        _updateInfo = await UpdateService.CheckForUpdateAsync();
        if (_updateInfo == null)
            return;

        UpdateText.Text = $"Update available: v{_updateInfo.CurrentVersion} \u2192 v{_updateInfo.LatestVersion}";
        UpdateSubText.Text = _updateInfo.Ps1DownloadUrl != null
            ? "Updates both the GUI and Run-Audit.ps1"
            : "Updates the GUI executable";
        UpdateBanner.Visibility = Visibility.Visible;
    }

    private async void UpdateButton_Click(object sender, RoutedEventArgs e)
    {
        if (_updateInfo == null) return;

        UpdateButton.IsEnabled = false;
        UpdateButton.Content = "Downloading...";

        var success = await UpdateService.DownloadAndRestartAsync(_updateInfo, status =>
        {
            Dispatcher.Invoke(() => UpdateSubText.Text = status);
        });

        if (success)
        {
            Application.Current.Shutdown();
        }
        else
        {
            UpdateButton.IsEnabled = true;
            UpdateButton.Content = "Update && Restart";
            UpdateSubText.Text = "Update failed. Try again or download manually.";
        }
    }

    private async void DownloadScriptButton_Click(object sender, RoutedEventArgs e)
    {
        DownloadScriptButton.IsEnabled = false;
        DownloadScriptButton.Content = "Downloading...";

        var success = await UpdateService.DownloadScriptAsync(status =>
        {
            Dispatcher.Invoke(() => ScriptStatusText.Text = status);
        });

        if (success)
        {
            // Re-check script status and update UI
            var runner = new AuditRunner();
            if (runner.FindScript() != null)
            {
                ScriptStatusText.Text = "Run-Audit.ps1 found";
                ScriptStatusText.Foreground = FindResource("GoodBrush") as SolidColorBrush;
                ScriptStatusBorder.Background = new SolidColorBrush(Color.FromArgb(0x1A, 0x05, 0x96, 0x69));
                DownloadScriptButton.Visibility = Visibility.Collapsed;
                RunButton.IsEnabled = true;
            }
        }
        else
        {
            ScriptStatusText.Text = "Download failed - check your internet connection";
            DownloadScriptButton.IsEnabled = true;
            DownloadScriptButton.Content = "Retry";
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
