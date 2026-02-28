namespace SecureJournal.Web.Services;

public sealed record StoreListQuery(
    string FilterText,
    string SortField,
    bool SortDescending,
    int Page,
    int PageSize,
    bool? Assigned = null);

public sealed record StorePagedResult<T>(
    IReadOnlyList<T> Items,
    int TotalCount);

public sealed record StoredGroupAccessRow(
    Guid GroupId,
    string Name,
    string Description,
    bool IsAssigned);

public sealed record StoredProjectGroupNameRow(
    Guid ProjectId,
    string GroupName);

public sealed record StoredUserGroupNameRow(
    Guid UserId,
    string GroupName);

public sealed record StoredGroupMemberNameRow(
    Guid GroupId,
    string DisplayName);

public sealed record StoredGroupProjectCodeRow(
    Guid GroupId,
    string ProjectCode);
