namespace SecureJournal.Core.Domain;

public enum AuditActionType
{
    Create = 1,
    Read = 2,
    Update = 3,
    Delete = 4,
    Login = 5,
    Logout = 6,
    Assign = 7,
    Export = 8,
    AccessDenied = 9,
    Configure = 10
}

public enum AuditEntityType
{
    JournalEntry = 1,
    User = 2,
    Group = 3,
    Project = 4,
    Permission = 5,
    Authentication = 6,
    Export = 7
}

public enum AuditOutcome
{
    Success = 1,
    Failure = 2,
    Denied = 3
}
