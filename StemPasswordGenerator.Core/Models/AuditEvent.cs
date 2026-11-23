namespace StemPasswordGenerator.Models;

public sealed class AuditEvent
{
    public DateTimeOffset Utc { get; set; }

    public string Kind { get; set; } = string.Empty;

    public string Method { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string ItemKind { get; set; } = string.Empty;

    public Guid? ItemId { get; set; }
}

public static class AuditKind
{
    public const string UnlockFail = "unlock-fail";
    public const string UnlockOk = "unlock-ok";
    public const string Used = "used";
    public const string Created = "created";
    public const string Updated = "updated";
    public const string Deleted = "deleted";
    public const string PasswordChanged = "password-changed";
    public const string Imported = "imported";
    public const string MediaAdded = "media-added";
    public const string MediaExported = "media-exported";
}

public static class AuditMethod
{
    public const string Master = "master";
    public const string Hello = "hello";
    public const string HelloCancel = "hello-cancel";
    public const string Usb = "usb";
    public const string Recovery = "recovery";
    public const string Human = "human";
    public const string Copy = "copy";
    public const string Autofill = "autofill";
    public const string Export = "export";
}

public static class AuditBucket
{
    public const string All = "all";
    public const string Fail = "fail";
    public const string Use = "use";
    public const string Entry = "entry";
}
