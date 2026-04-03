using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using WindowsAuditTool.Models;

namespace WindowsAuditTool.Services;

/// <summary>
/// Runs Run-Audit.ps1 as a child process, captures stdout, and parses progress.
/// </summary>
public sealed class AuditRunner : IDisposable
{
    private const string ScriptName = "Run-Audit.ps1";

    // Regex patterns for parsing script output
    private static readonly Regex StepPattern = new(@"^\[(\d+)/(\d+)\]\s+(.+)$", RegexOptions.Compiled);
    private static readonly Regex ActionPattern = new(@"^    - (.+)$", RegexOptions.Compiled);
    private static readonly Regex ReportSavedPattern = new(@"^HTML report saved to (.+)$", RegexOptions.Compiled);
    private static readonly Regex CompletedPattern = new(@"^=== Audit Completed", RegexOptions.Compiled);
    private static readonly Regex ElevatedPattern = new(@"^\[0\] Elevated:\s*(Yes|No)", RegexOptions.Compiled);

    private Process? _process;
    private CancellationTokenSource? _cts;

    /// <summary>Raised for each raw output line from the script.</summary>
    public event Action<string>? OutputReceived;

    /// <summary>Raised when a step progress line is parsed.</summary>
    public event Action<AuditProgress>? StepChanged;

    /// <summary>Raised when an action line is parsed.</summary>
    public event Action<AuditAction>? ActionReceived;

    /// <summary>Raised when the audit completes (with exit code).</summary>
    public event Action<int, string?>? Completed;

    /// <summary>The report file path captured from script output.</summary>
    public string? ReportPath { get; private set; }

    public string? FindScript()
    {
        var dir = AppContext.BaseDirectory;
        var path = Path.Combine(dir, ScriptName);
        return File.Exists(path) ? path : null;
    }

    public async Task RunAsync(AppConfig config)
    {
        var scriptPath = FindScript()
            ?? throw new FileNotFoundException($"{ScriptName} not found next to the application executable.");

        _cts = new CancellationTokenSource();
        ReportPath = null;

        var args = BuildArguments(scriptPath, config);

        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
            StandardErrorEncoding = System.Text.Encoding.UTF8
        };

        _process = new Process { StartInfo = psi, EnableRaisingEvents = true };

        var tcs = new TaskCompletionSource<int>();

        _process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null)
                ProcessLine(e.Data);
        };

        _process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
                OutputReceived?.Invoke($"[stderr] {e.Data}");
        };

        _process.Exited += (_, _) =>
        {
            try
            {
                tcs.TrySetResult(_process.ExitCode);
            }
            catch
            {
                tcs.TrySetResult(-1);
            }
        };

        _process.Start();
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();

        using var reg = _cts.Token.Register(() =>
        {
            try { if (!_process.HasExited) _process.Kill(entireProcessTree: true); }
            catch { /* process already exited */ }
        });

        var exitCode = await tcs.Task;
        Completed?.Invoke(exitCode, ReportPath);
    }

    public void Cancel()
    {
        _cts?.Cancel();
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _process?.Dispose();
    }

    private static string BuildArguments(string scriptPath, AppConfig config)
    {
        var parts = new List<string>
        {
            "-ExecutionPolicy", "Bypass",
            "-File", $"\"{scriptPath}\"",
            "-Silent"
        };

        if (!string.IsNullOrWhiteSpace(config.CustomerName))
        {
            parts.Add("-CustomerName");
            parts.Add($"\"{config.CustomerName}\"");
        }

        if (config.HuduReport)
        {
            parts.Add("-HuduReport");

            if (!string.IsNullOrWhiteSpace(config.HuduAPIKey))
            {
                parts.Add("-HuduAPIKey");
                parts.Add($"\"{config.HuduAPIKey}\"");
            }
            if (!string.IsNullOrWhiteSpace(config.HuduBaseURL))
            {
                parts.Add("-HuduBaseURL");
                parts.Add($"\"{config.HuduBaseURL}\"");
            }
            if (!string.IsNullOrWhiteSpace(config.HuduCompanySlug))
            {
                parts.Add("-HuduCompanySlug");
                parts.Add($"\"{config.HuduCompanySlug}\"");
            }
            if (!string.IsNullOrWhiteSpace(config.HuduAssetLayoutName))
            {
                parts.Add("-HuduAssetLayoutName");
                parts.Add($"\"{config.HuduAssetLayoutName}\"");
            }
            if (!string.IsNullOrWhiteSpace(config.HuduEntryName))
            {
                parts.Add("-HuduEntryName");
                parts.Add($"\"{config.HuduEntryName}\"");
            }
        }

        return string.Join(' ', parts);
    }

    private void ProcessLine(string line)
    {
        OutputReceived?.Invoke(line);

        // [N/13] Step title
        var stepMatch = StepPattern.Match(line);
        if (stepMatch.Success)
        {
            StepChanged?.Invoke(new AuditProgress
            {
                StepIndex = int.Parse(stepMatch.Groups[1].Value),
                StepTotal = int.Parse(stepMatch.Groups[2].Value),
                StepTitle = stepMatch.Groups[3].Value
            });
            return;
        }

        //     - Action text
        var actionMatch = ActionPattern.Match(line);
        if (actionMatch.Success)
        {
            var text = actionMatch.Groups[1].Value;
            ActionReceived?.Invoke(new AuditAction
            {
                Text = text,
                Kind = ClassifyAction(text)
            });
            return;
        }

        // HTML report saved to <path>
        var reportMatch = ReportSavedPattern.Match(line);
        if (reportMatch.Success)
        {
            ReportPath = reportMatch.Groups[1].Value.Trim();
            return;
        }

        // Elevation status
        var elevMatch = ElevatedPattern.Match(line);
        if (elevMatch.Success)
        {
            // Could raise an event here if needed
            return;
        }
    }

    private static ActionKind ClassifyAction(string text)
    {
        if (text.StartsWith("Running:", StringComparison.OrdinalIgnoreCase))
            return ActionKind.Run;
        if (text.StartsWith("Skipped", StringComparison.OrdinalIgnoreCase))
            return ActionKind.Skip;
        if (text.Contains("failed", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("error", StringComparison.OrdinalIgnoreCase))
            return ActionKind.Bad;
        if (text.Contains("warning", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("not elevated", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("not protected", StringComparison.OrdinalIgnoreCase))
            return ActionKind.Warn;
        if (text.Contains("found:", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("Protection ON", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("Enabled", StringComparison.OrdinalIgnoreCase))
            return ActionKind.Ok;

        return ActionKind.Info;
    }
}
