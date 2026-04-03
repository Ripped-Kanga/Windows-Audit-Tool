using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
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

            ReportWebView.CoreWebView2.NavigationCompleted += async (_, args) =>
            {
                if (args.IsSuccess)
                    await ExportPdfAsync();
            };

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
        StatusLabel.Foreground = FindResource("BadBrush") as SolidColorBrush;
        ReportWebView.Visibility = Visibility.Collapsed;
        FallbackPanel.Visibility = Visibility.Visible;
        FallbackPath.Text = message;
        OpenBrowserButton.IsEnabled = false;
        OpenFolderButton.IsEnabled = false;
    }

    private async System.Threading.Tasks.Task ExportPdfAsync()
    {
        if (_reportPath == null || ReportWebView.CoreWebView2 == null)
            return;

        var pdfPath = Path.ChangeExtension(_reportPath, ".pdf");
        PdfStatus.Text = "Saving PDF...";
        PdfStatus.Foreground = FindResource("MutedBrush") as SolidColorBrush;

        try
        {
            // Inject CSS to fix large blank spaces caused by break-inside:avoid on tall sections
            await ReportWebView.CoreWebView2.ExecuteScriptAsync(@"
                (() => {
                    const style = document.createElement('style');
                    style.textContent = `
                        @media print {
                            .section, .score-card { break-inside: auto !important; }
                            table { break-inside: auto !important; }
                            tr { break-inside: avoid; }
                            h2 { break-after: avoid; }
                        }
                    `;
                    document.head.appendChild(style);
                })()
            ");

            var printSettings = ReportWebView.CoreWebView2.Environment.CreatePrintSettings();
            printSettings.Orientation = CoreWebView2PrintOrientation.Portrait;
            printSettings.ShouldPrintBackgrounds = true;
            printSettings.MarginTop = 0.4;
            printSettings.MarginBottom = 0.4;
            printSettings.MarginLeft = 0.4;
            printSettings.MarginRight = 0.4;

            var result = await ReportWebView.CoreWebView2.PrintToPdfAsync(pdfPath, printSettings);

            if (result)
            {
                PdfStatus.Text = $"PDF saved";
                PdfStatus.Foreground = FindResource("GoodBrush") as SolidColorBrush;
            }
            else
            {
                PdfStatus.Text = "PDF export failed";
                PdfStatus.Foreground = FindResource("BadBrush") as SolidColorBrush;
            }
        }
        catch
        {
            PdfStatus.Text = "PDF export failed";
            PdfStatus.Foreground = FindResource("BadBrush") as SolidColorBrush;
        }
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
