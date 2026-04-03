using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace WindowsAuditTool.Services;

/// <summary>
/// Checks the GitHub Releases API for a newer GUI version, downloads it,
/// and orchestrates the swap-and-restart sequence.
/// </summary>
public sealed class UpdateService
{
    private const string ApiUrl = "https://api.github.com/repos/Ripped-Kanga/Windows-Audit-Tool/releases/latest";
    private const string PendingFileName = "WindowsAuditTool.exe.update";

    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(15),
        DefaultRequestHeaders =
        {
            { "User-Agent", "WindowsAuditTool-GUI" },
            { "Accept", "application/vnd.github.v3+json" }
        }
    };

    /// <summary>
    /// On startup, if a previous update left a .update file, swap it into place.
    /// Must be called before any other operation touches the exe path.
    /// Returns true if a swap was applied (caller may want to log this).
    /// </summary>
    public static bool ApplyPendingUpdate()
    {
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath))
            return false;

        var pendingPath = Path.Combine(Path.GetDirectoryName(exePath)!, PendingFileName);
        if (!File.Exists(pendingPath))
            return false;

        try
        {
            var backupPath = exePath + ".old";
            // Remove stale backup from a prior cycle
            if (File.Exists(backupPath))
                File.Delete(backupPath);

            File.Move(exePath, backupPath);
            File.Move(pendingPath, exePath);

            // Clean up backup -- not critical if this fails
            try { File.Delete(backupPath); } catch { }

            return true;
        }
        catch
        {
            // Swap failed -- leave the pending file for next attempt
            return false;
        }
    }

    /// <summary>
    /// Queries the GitHub Releases API for a newer version.
    /// Returns null on any failure (network, parse, etc.) -- never throws.
    /// </summary>
    public static async Task<UpdateInfo?> CheckForUpdateAsync()
    {
        try
        {
            var release = await Http.GetFromJsonAsync<GitHubRelease>(ApiUrl);
            if (release?.TagName == null)
                return null;

            var latestClean = release.TagName.TrimStart('v');
            var currentVersion = GetCurrentVersion();

            bool isNewer;
            try
            {
                isNewer = new Version(latestClean) > new Version(currentVersion);
            }
            catch
            {
                // Version string not parseable -- treat as different
                isNewer = latestClean != currentVersion;
            }

            if (!isNewer)
                return null;

            // Find the GUI exe asset
            var guiAsset = release.Assets?.FirstOrDefault(a =>
                a.Name != null && a.Name.Equals("WindowsAuditTool.exe", StringComparison.OrdinalIgnoreCase));

            // Also grab the ps1 if present
            var ps1Asset = release.Assets?.FirstOrDefault(a =>
                a.Name != null && a.Name.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase));

            return new UpdateInfo
            {
                LatestVersion = latestClean,
                CurrentVersion = currentVersion,
                ReleaseUrl = release.HtmlUrl ?? "",
                GuiDownloadUrl = guiAsset?.BrowserDownloadUrl,
                Ps1DownloadUrl = ps1Asset?.BrowserDownloadUrl
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Downloads the new GUI exe and ps1 to the application directory,
    /// then launches a helper process that waits for us to exit, swaps the
    /// files, and relaunches.
    /// </summary>
    public static async Task<bool> DownloadAndRestartAsync(UpdateInfo info, Action<string>? progress = null)
    {
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath))
            return false;

        var appDir = Path.GetDirectoryName(exePath)!;
        var pendingExePath = Path.Combine(appDir, PendingFileName);

        try
        {
            // Download GUI exe
            if (!string.IsNullOrEmpty(info.GuiDownloadUrl))
            {
                progress?.Invoke("Downloading WindowsAuditTool.exe...");
                using var response = await Http.GetAsync(info.GuiDownloadUrl, HttpCompletionOption.ResponseHeadersRead);
                response.EnsureSuccessStatusCode();
                await using var fs = File.Create(pendingExePath);
                await response.Content.CopyToAsync(fs);
            }
            else
            {
                return false;
            }

            // Download updated ps1 alongside
            if (!string.IsNullOrEmpty(info.Ps1DownloadUrl))
            {
                progress?.Invoke("Downloading Run-Audit.ps1...");
                var ps1Path = Path.Combine(appDir, "Run-Audit.ps1");
                using var response = await Http.GetAsync(info.Ps1DownloadUrl, HttpCompletionOption.ResponseHeadersRead);
                response.EnsureSuccessStatusCode();
                await using var fs = File.Create(ps1Path);
                await response.Content.CopyToAsync(fs);
            }

            // Launch a PowerShell process that waits for us to exit, swaps the exe, and relaunches
            progress?.Invoke("Restarting...");
            var pid = Environment.ProcessId;
            var script = string.Join("; ",
                $"$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue",
                "if ($p) { $p.WaitForExit(30000) }",
                $"if (Test-Path '{pendingExePath}') {{",
                $"  $backup = '{exePath}.old'",
                "  if (Test-Path $backup) { Remove-Item $backup -Force -ErrorAction SilentlyContinue }",
                $"  Move-Item -LiteralPath '{exePath}' -Destination $backup -Force",
                $"  Move-Item -LiteralPath '{pendingExePath}' -Destination '{exePath}' -Force",
                "  Remove-Item $backup -Force -ErrorAction SilentlyContinue",
                "}",
                $"Start-Process '{exePath}'"
            );

            Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-WindowStyle Hidden -ExecutionPolicy Bypass -Command \"{script}\"",
                UseShellExecute = false,
                CreateNoWindow = true
            });

            return true;
        }
        catch
        {
            // Clean up partial download
            try { if (File.Exists(pendingExePath)) File.Delete(pendingExePath); } catch { }
            return false;
        }
    }

    /// <summary>
    /// Downloads Run-Audit.ps1 from the latest GitHub release into the application directory.
    /// Returns true on success.
    /// </summary>
    public static async Task<bool> DownloadScriptAsync(Action<string>? progress = null)
    {
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath))
            return false;

        var appDir = Path.GetDirectoryName(exePath)!;

        try
        {
            progress?.Invoke("Checking latest release...");
            var release = await Http.GetFromJsonAsync<GitHubRelease>(ApiUrl);
            if (release?.Assets == null)
                return false;

            var ps1Asset = release.Assets.FirstOrDefault(a =>
                a.Name != null && a.Name.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase));

            if (ps1Asset?.BrowserDownloadUrl == null)
                return false;

            progress?.Invoke("Downloading Run-Audit.ps1...");
            var ps1Path = Path.Combine(appDir, "Run-Audit.ps1");
            using var response = await Http.GetAsync(ps1Asset.BrowserDownloadUrl, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();
            await using var fs = File.Create(ps1Path);
            await response.Content.CopyToAsync(fs);

            progress?.Invoke("Download complete.");
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string GetCurrentVersion()
    {
        var asm = System.Reflection.Assembly.GetExecutingAssembly();
        var ver = asm.GetName().Version;
        return ver != null ? ver.ToString() : "0.0.0.0";
    }

    // JSON models for the GitHub API response
    private sealed class GitHubRelease
    {
        [JsonPropertyName("tag_name")]
        public string? TagName { get; set; }

        [JsonPropertyName("html_url")]
        public string? HtmlUrl { get; set; }

        [JsonPropertyName("assets")]
        public GitHubAsset[]? Assets { get; set; }
    }

    private sealed class GitHubAsset
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("browser_download_url")]
        public string? BrowserDownloadUrl { get; set; }
    }
}

public sealed class UpdateInfo
{
    public string LatestVersion { get; init; } = "";
    public string CurrentVersion { get; init; } = "";
    public string ReleaseUrl { get; init; } = "";
    public string? GuiDownloadUrl { get; init; }
    public string? Ps1DownloadUrl { get; init; }
}
