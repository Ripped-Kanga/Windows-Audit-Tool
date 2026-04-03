using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using WindowsAuditTool.Models;
using WindowsAuditTool.Services;

namespace WindowsAuditTool.Views;

public partial class ProgressView : UserControl
{
    private AuditRunner? _runner;
    private readonly ObservableCollection<LogEntry> _logEntries = [];

    /// <summary>Raised when the audit finishes (exit code, report path).</summary>
    public event Action<int, string?>? AuditCompleted;

    /// <summary>Raised when the user cancels.</summary>
    public event Action? AuditCancelled;

    public ProgressView()
    {
        InitializeComponent();
        LogItems.ItemsSource = _logEntries;
    }

    public async Task StartAudit(AppConfig config)
    {
        _logEntries.Clear();
        ProgressBar.Value = 0;
        StepCounter.Text = "0/13";
        StepTitle.Text = "Starting...";
        StatusText.Text = "Launching PowerShell...";
        CancelButton.IsEnabled = true;

        _runner = new AuditRunner();

        _runner.OutputReceived += line =>
        {
            Dispatcher.Invoke(() => AddLogEntry(line, Brushes.Gray));
        };

        _runner.StepChanged += progress =>
        {
            Dispatcher.Invoke(() =>
            {
                ProgressBar.Value = progress.StepIndex;
                ProgressBar.Maximum = progress.StepTotal;
                StepCounter.Text = $"{progress.StepIndex}/{progress.StepTotal}";
                StepTitle.Text = progress.StepTitle;
                StatusText.Text = $"Step {progress.StepIndex} of {progress.StepTotal}";
            });
        };

        _runner.ActionReceived += action =>
        {
            Dispatcher.Invoke(() =>
            {
                var brush = action.Kind switch
                {
                    ActionKind.Run  => new SolidColorBrush(Color.FromRgb(0x00, 0xBC, 0xD4)),
                    ActionKind.Ok   => new SolidColorBrush(Color.FromRgb(0x05, 0x96, 0x69)),
                    ActionKind.Warn => new SolidColorBrush(Color.FromRgb(0xD9, 0x77, 0x06)),
                    ActionKind.Bad  => new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26)),
                    ActionKind.Skip => new SolidColorBrush(Color.FromRgb(0x9C, 0x8B, 0x00)),
                    _               => new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B)),
                };
                AddLogEntry($"    {action.Text}", brush);
            });
        };

        _runner.Completed += (exitCode, reportPath) =>
        {
            Dispatcher.Invoke(() =>
            {
                CancelButton.IsEnabled = false;
                if (exitCode == 0)
                {
                    StatusText.Text = "Audit completed successfully.";
                    ProgressBar.Foreground = FindResource("GoodBrush") as SolidColorBrush;
                }
                else
                {
                    StatusText.Text = $"Audit finished with exit code {exitCode}.";
                    ProgressBar.Foreground = FindResource("BadBrush") as SolidColorBrush;
                }
                AuditCompleted?.Invoke(exitCode, reportPath);
            });
        };

        try
        {
            await _runner.RunAsync(config);
        }
        catch (Exception ex)
        {
            AddLogEntry($"ERROR: {ex.Message}", Brushes.Red);
            StatusText.Text = "Audit failed to start.";
            CancelButton.IsEnabled = false;
            AuditCompleted?.Invoke(-1, null);
        }
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        _runner?.Cancel();
        CancelButton.IsEnabled = false;
        StatusText.Text = "Cancelling...";
        AuditCancelled?.Invoke();
    }

    private void AddLogEntry(string text, Brush brush)
    {
        _logEntries.Add(new LogEntry { Text = text, Brush = brush });

        // Auto-scroll to bottom
        if (LogScroller.VerticalOffset >= LogScroller.ScrollableHeight - 20)
        {
            LogScroller.ScrollToEnd();
        }
    }
}

/// <summary>A single log line in the progress view.</summary>
public sealed class LogEntry
{
    public string Text { get; init; } = string.Empty;
    public Brush Brush { get; init; } = Brushes.Gray;
}
