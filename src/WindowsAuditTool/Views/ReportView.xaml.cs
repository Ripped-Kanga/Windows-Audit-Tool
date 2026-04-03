using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Web.WebView2.Core;

namespace WindowsAuditTool.Views;

public partial class ReportView : UserControl
{
    private string? _reportPath;
    private bool _webView2Available;

    /// <summary>Raised when the user clicks "Run Again".</summary>
    public event Action? RunAgainRequested;

    public ReportView()
    {
        InitializeComponent();
    }

    public async void LoadReport(string reportPath)
    {
        _reportPath = reportPath;

        if (!File.Exists(reportPath))
        {
            ShowFallback($"Report file not found: {reportPath}");
            return;
        }

        try
        {
            // Initialize WebView2 with a temp user data folder (no persistent state)
            var env = await CoreWebView2Environment.CreateAsync(
                userDataFolder: Path.Combine(Path.GetTempPath(), "WindowsAuditTool_WebView2"));
            await ReportWebView.EnsureCoreWebView2Async(env);

            _webView2Available = true;
            ReportWebView.Visibility = Visibility.Visible;
            FallbackPanel.Visibility = Visibility.Collapsed;

            ReportWebView.CoreWebView2.Navigate(new Uri(reportPath).AbsoluteUri);
        }
        catch (Exception)
        {
            // WebView2 runtime not installed - fall back to default browser
            _webView2Available = false;
            ShowFallback(reportPath);
            OpenInBrowser(reportPath);
        }
    }

    public void ShowError(string message)
    {
        StatusLabel.Text = "Audit Failed";
        StatusLabel.Foreground = FindResource("BadBrush") as System.Windows.Media.SolidColorBrush;
        ReportWebView.Visibility = Visibility.Collapsed;
        FallbackPanel.Visibility = Visibility.Visible;
        FallbackPath.Text = message;
        OpenBrowserButton.IsEnabled = false;
        OpenFolderButton.IsEnabled = false;
        PrintButton.IsEnabled = false;
    }

    private void ShowFallback(string reportPath)
    {
        ReportWebView.Visibility = Visibility.Collapsed;
        FallbackPanel.Visibility = Visibility.Visible;
        FallbackPath.Text = reportPath;
    }

    private void OpenBrowserButton_Click(object sender, RoutedEventArgs e)
    {
        if (_reportPath != null)
            OpenInBrowser(_reportPath);
    }

    private void OpenFolderButton_Click(object sender, RoutedEventArgs e)
    {
        if (_reportPath == null) return;

        var dir = Path.GetDirectoryName(_reportPath);
        if (dir != null && Directory.Exists(dir))
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"/select,\"{_reportPath}\"",
                UseShellExecute = true
            });
        }
    }

    private void PrintButton_Click(object sender, RoutedEventArgs e)
    {
        if (_webView2Available && ReportWebView.CoreWebView2 != null)
        {
            ReportWebView.CoreWebView2.ExecuteScriptAsync("window.print()");
        }
    }

    private void RunAgainButton_Click(object sender, RoutedEventArgs e)
    {
        RunAgainRequested?.Invoke();
    }

    private static void OpenInBrowser(string path)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
        }
        catch { /* ignore - browser may not handle .html */ }
    }
}
