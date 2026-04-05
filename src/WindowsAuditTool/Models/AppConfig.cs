namespace WindowsAuditTool.Models;

/// <summary>
/// Settings loaded from config.txt (optional file alongside the exe).
/// </summary>
public sealed class AppConfig
{
    public string CustomerName { get; set; } = string.Empty;
    public bool HuduReport { get; set; }
    public string HuduAPIKey { get; set; } = string.Empty;
    public string HuduBaseURL { get; set; } = string.Empty;
    public string HuduCompanySlug { get; set; } = string.Empty;
    public string HuduAssetLayoutName { get; set; } = string.Empty;
    public string HuduEntryName { get; set; } = string.Empty;
    public string HuduReportName { get; set; } = string.Empty;
}
