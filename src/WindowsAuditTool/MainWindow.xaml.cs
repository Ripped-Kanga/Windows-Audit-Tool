using System.Windows;
using WindowsAuditTool.Models;
using WindowsAuditTool.Services;

namespace WindowsAuditTool;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        LaunchView.RunRequested += OnRunRequested;
        ProgressView.AuditCompleted += OnAuditCompleted;
        ProgressView.AuditCancelled += OnAuditCancelled;
        ReportView.RunAgainRequested += OnRunAgainRequested;
    }

    private async void OnRunRequested(AppConfig config)
    {
        ShowView(ViewState.Progress);
        await ProgressView.StartAudit(config);
    }

    private void OnAuditCompleted(int exitCode, string? reportPath)
    {
        // Try to find the report even if the path wasn't captured from output
        reportPath ??= ReportLocator.FindReport();

        if (exitCode == 0 && reportPath != null)
        {
            ShowView(ViewState.Report);
            ReportView.LoadReport(reportPath);
        }
        else if (reportPath != null)
        {
            // Non-zero exit but report exists (partial success)
            ShowView(ViewState.Report);
            ReportView.LoadReport(reportPath);
        }
        else
        {
            ShowView(ViewState.Report);
            ReportView.ShowError(
                exitCode == 0
                    ? "Audit completed but no report file was found."
                    : $"Audit failed with exit code {exitCode}. No report was generated.");
        }
    }

    private void OnAuditCancelled()
    {
        ShowView(ViewState.Launch);
    }

    private void OnRunAgainRequested()
    {
        ShowView(ViewState.Launch);
    }

    private void ShowView(ViewState state)
    {
        LaunchView.Visibility = state == ViewState.Launch ? Visibility.Visible : Visibility.Collapsed;
        ProgressView.Visibility = state == ViewState.Progress ? Visibility.Visible : Visibility.Collapsed;
        ReportView.Visibility = state == ViewState.Report ? Visibility.Visible : Visibility.Collapsed;
    }

    private enum ViewState
    {
        Launch,
        Progress,
        Report
    }
}
