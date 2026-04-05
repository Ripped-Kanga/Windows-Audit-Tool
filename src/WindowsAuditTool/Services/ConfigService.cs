using System;
using System.IO;
using WindowsAuditTool.Models;

namespace WindowsAuditTool.Services;

/// <summary>
/// Reads an optional config.txt file from the application directory.
/// Format: key=value, one per line. Lines starting with # are comments.
/// </summary>
public static class ConfigService
{
    private const string FileName = "config.txt";

    public static AppConfig Load()
    {
        var config = new AppConfig();
        var path = Path.Combine(AppContext.BaseDirectory, FileName);

        if (!File.Exists(path))
            return config;

        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (string.IsNullOrEmpty(line) || line.StartsWith('#'))
                continue;

            var sep = line.IndexOf('=');
            if (sep <= 0)
                continue;

            var key = line[..sep].Trim();
            var value = line[(sep + 1)..].Trim();

            switch (key.ToLowerInvariant())
            {
                case "customername":
                    config.CustomerName = value;
                    break;
                case "hudureport":
                    config.HuduReport = value.Equals("true", StringComparison.OrdinalIgnoreCase);
                    break;
                case "huduapikey":
                    config.HuduAPIKey = value;
                    break;
                case "hudubaseurl":
                    config.HuduBaseURL = value;
                    break;
                case "huducompanyslug":
                    config.HuduCompanySlug = value;
                    break;
                case "huduassetlayoutname":
                    config.HuduAssetLayoutName = value;
                    break;
                case "huduentryname":
                    config.HuduEntryName = value;
                    break;
                case "hudureportname":
                    config.HuduReportName = value;
                    break;
            }
        }

        return config;
    }

    public static bool ConfigFileExists()
    {
        return File.Exists(Path.Combine(AppContext.BaseDirectory, FileName));
    }
}
