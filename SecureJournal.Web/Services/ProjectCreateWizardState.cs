using SecureJournal.Core.Application;

namespace SecureJournal.Web.Services;

public sealed class ProjectCreateWizardState
{
    public CreateProjectRequest ProjectDraft { get; } = new();
    public bool UseExistingGroups { get; set; } = true;
    public HashSet<Guid> SelectedExistingGroupIds { get; } = [];
    public List<WizardGroupDraft> NewGroups { get; } = [];

    public void Reset()
    {
        ProjectDraft.Code = string.Empty;
        ProjectDraft.Name = string.Empty;
        ProjectDraft.Description = string.Empty;
        ProjectDraft.ProjectEmail = string.Empty;
        ProjectDraft.ProjectPhone = string.Empty;
        ProjectDraft.ProjectOwner = string.Empty;
        ProjectDraft.Department = string.Empty;

        UseExistingGroups = true;
        SelectedExistingGroupIds.Clear();
        NewGroups.Clear();
    }
}

public sealed class WizardGroupDraft
{
    public Guid DraftId { get; init; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public HashSet<Guid> MemberUserIds { get; } = [];
}
