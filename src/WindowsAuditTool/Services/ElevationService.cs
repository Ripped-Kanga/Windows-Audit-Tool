using System;
using System.Diagnostics;
using System.Security.Principal;

namespace WindowsAuditTool.Services;

/// <summary>
/// Checks whether the current process is elevated and can restart with admin rights.
/// </summary>
public static class ElevationService
{
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Restarts the current executable with UAC elevation (runas verb).
    /// Returns true if the elevated process was started; false if the user cancelled UAC.
    /// </summary>
    public static bool RestartElevated()
    {
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath))
            return false;

        var psi = new ProcessStartInfo
        {
            FileName = exePath,
            UseShellExecute = true,
            Verb = "runas"
        };

        try
        {
            Process.Start(psi);
            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // User cancelled UAC dialog
            return false;
        }
    }
}
