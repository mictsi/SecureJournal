namespace SecureJournal.Core.Application;

public enum SortDirection
{
    Asc,
    Desc
}

public sealed record PagedResult<T>(
    IReadOnlyList<T> Items,
    int TotalCount,
    int Page,
    int PageSize,
    int TotalPages);

public sealed class ProjectListQuery
{
    public string FilterText { get; set; } = string.Empty;
    public string SortField { get; set; } = "code";
    public SortDirection SortDirection { get; set; } = SortDirection.Asc;
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 30;
}

public sealed class UserListQuery
{
    public string FilterText { get; set; } = string.Empty;
    public string SortField { get; set; } = "username";
    public SortDirection SortDirection { get; set; } = SortDirection.Asc;
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 30;
}

public sealed class GroupListQuery
{
    public string FilterText { get; set; } = string.Empty;
    public string SortField { get; set; } = "name";
    public SortDirection SortDirection { get; set; } = SortDirection.Asc;
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 30;
}

public sealed class ProjectGroupAccessQuery
{
    public Guid ProjectId { get; set; }
    public string FilterText { get; set; } = string.Empty;
    public string SortField { get; set; } = "name";
    public SortDirection SortDirection { get; set; } = SortDirection.Asc;
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 30;
}

public sealed class UserGroupMembershipQuery
{
    public Guid UserId { get; set; }
    public string FilterText { get; set; } = string.Empty;
    public bool? Assigned { get; set; }
    public string SortField { get; set; } = "name";
    public SortDirection SortDirection { get; set; } = SortDirection.Asc;
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 30;
}

public sealed record GroupAccessRow(
    Guid GroupId,
    string Name,
    string Description,
    bool IsAssigned);
