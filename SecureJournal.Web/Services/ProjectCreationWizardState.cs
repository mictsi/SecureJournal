using SecureJournal.Core.Application;

namespace SecureJournal.Web.Services;

public sealed class ProjectCreationWizardState
{
    public CreateProjectRequest ProjectDraft { get; } = new();
    public bool CreateNewGroup { get; set; }
    public CreateGroupRequest NewGroupDraft { get; } = new();
    public HashSet<Guid> SelectedExistingGroupIds { get; } = [];
    public HashSet<Guid> SelectedNewGroupMemberIds { get; } = [];

    public bool HasProjectDetails()
        => !string.IsNullOrWhiteSpace(ProjectDraft.Name);

    public string Complete(ISecureJournalAppService journalApp)
    {
        ArgumentNullException.ThrowIfNull(journalApp);

        var project = journalApp.CreateProject(ProjectDraft);
        var targetGroupIds = new HashSet<Guid>(SelectedExistingGroupIds);

        if (CreateNewGroup)
        {
            var group = journalApp.CreateGroup(NewGroupDraft);
            targetGroupIds.Add(group.GroupId);

            foreach (var userId in SelectedNewGroupMemberIds)
            {
                journalApp.AssignUserToGroup(new AssignUserToGroupRequest
                {
                    UserId = userId,
                    GroupId = group.GroupId
                });
            }
        }

        foreach (var groupId in targetGroupIds)
        {
            journalApp.AssignGroupToProject(new AssignGroupToProjectRequest
            {
                ProjectId = project.ProjectId,
                GroupId = groupId
            });
        }

        return project.Code;
    }

    public void Reset()
    {
        ProjectDraft.Code = string.Empty;
        ProjectDraft.Name = string.Empty;
        ProjectDraft.Description = string.Empty;
        ProjectDraft.ProjectEmail = string.Empty;
        ProjectDraft.ProjectPhone = string.Empty;
        ProjectDraft.ProjectOwner = string.Empty;
        ProjectDraft.Department = string.Empty;

        CreateNewGroup = false;
        NewGroupDraft.Name = string.Empty;
        NewGroupDraft.Description = string.Empty;
        SelectedExistingGroupIds.Clear();
        SelectedNewGroupMemberIds.Clear();
    }
}
