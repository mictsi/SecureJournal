using SecureJournal.Web.Services;
using Xunit;

namespace SecureJournal.Tests;

public sealed class ProjectCreateWizardStateTests
{
    [Fact]
    public void Reset_ClearsProjectAndGroupSelections()
    {
        var state = new ProjectCreateWizardState();
        state.ProjectDraft.Name = "Project Alpha";
        state.ProjectDraft.Description = "Pilot";
        state.UseExistingGroups = false;
        state.SelectedExistingGroupIds.Add(Guid.NewGuid());
        state.NewGroups.Add(new WizardGroupDraft { Name = "Blue Team", Description = "Reviewers" });

        state.Reset();

        Assert.True(state.UseExistingGroups);
        Assert.Empty(state.ProjectDraft.Name);
        Assert.Empty(state.ProjectDraft.Description);
        Assert.Empty(state.SelectedExistingGroupIds);
        Assert.Empty(state.NewGroups);
    }

    [Fact]
    public void WizardGroupDraft_TracksMemberSelections()
    {
        var memberId = Guid.NewGuid();
        var draft = new WizardGroupDraft { Name = "Approvers" };

        draft.MemberUserIds.Add(memberId);

        Assert.Contains(memberId, draft.MemberUserIds);
    }
}
