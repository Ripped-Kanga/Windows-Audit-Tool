using System.Windows;
using WindowsAuditTool.Services;

namespace WindowsAuditTool;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // Swap in a pending update from a previous download before anything else runs
        UpdateService.ApplyPendingUpdate();

        base.OnStartup(e);
    }
}
