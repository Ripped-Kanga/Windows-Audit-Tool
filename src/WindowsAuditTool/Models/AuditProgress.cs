namespace WindowsAuditTool.Models;

/// <summary>
/// Represents a parsed progress update from the audit script's stdout.
/// </summary>
public sealed class AuditProgress
{
    public int StepIndex { get; init; }
    public int StepTotal { get; init; }
    public string StepTitle { get; init; } = string.Empty;
}

/// <summary>
/// A single action line from the audit script (the "    - ..." lines).
/// </summary>
public sealed class AuditAction
{
    public string Text { get; init; } = string.Empty;
    public ActionKind Kind { get; init; }
}

public enum ActionKind
{
    Info,
    Run,
    Ok,
    Warn,
    Bad,
    Skip
}
