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

        ProjectOverview project;
        try
        {
            project = journalApp.CreateProject(ProjectDraft);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Project creation failed during wizard completion.", ex);
        }

        var targetGroupIds = new HashSet<Guid>(SelectedExistingGroupIds);

        if (CreateNewGroup)
        {
            GroupOverview group;
            try
            {
                group = journalApp.CreateGroup(NewGroupDraft);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("New group creation failed during wizard completion.", ex);
            }

            targetGroupIds.Add(group.GroupId);

            foreach (var userId in SelectedNewGroupMemberIds)
            {
                var added = journalApp.AssignUserToGroup(new AssignUserToGroupRequest
                {
                    UserId = userId,
                    GroupId = group.GroupId
                });

                if (!added)
                {
                    throw new InvalidOperationException($"Failed to add user '{userId}' to new group '{group.Name}'.");
                }
            }
        }

        foreach (var groupId in targetGroupIds)
        {
            var assigned = journalApp.AssignGroupToProject(new AssignGroupToProjectRequest
            {
                ProjectId = project.ProjectId,
                GroupId = groupId
            });

            if (!assigned)
            {
                throw new InvalidOperationException($"Failed to assign group '{groupId}' to project '{project.Code}'.");
            }
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
