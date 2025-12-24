package main

import (
	"context"

	"github.com/google/go-github/v71/github"
)

func (l *GithubReposPlugin) GatherOrgTeams(ctx context.Context) ([]*OrgTeam, error) {
	opts := &github.ListOptions{
		PerPage: 100,
		Page:    1,
	}

	var teams []*OrgTeam
	for {
		ghTeams, resp, err := l.githubClient.Teams.ListTeams(ctx, l.config.Organization, opts)
		if err != nil {
			if isPermissionError(err) {
				l.Logger.Debug("Organization teams fetch skipped due to permissions", "org", l.config.Organization, "error", err)
				return nil, nil
			}
			return nil, err
		}

		for _, team := range ghTeams {
			if team == nil {
				continue
			}

			members, err := l.listTeamMembers(ctx, team.GetSlug())
			if err != nil {
				l.Logger.Error("Could not get Team members for team", "team", team.GetSlug(), "error", err)
				continue
			}

			teams = append(teams, &OrgTeam{
				ID:      team.GetID(),
				Name:    team.GetName(),
				Slug:    team.GetSlug(),
				Members: members,
			})
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	l.Logger.Debug("Fetched organization teams", "teams", teams)
	return teams, nil
}

func (l *GithubReposPlugin) listTeamMembers(ctx context.Context, teamSlug string) ([]string, error) {
	opts := &github.TeamListTeamMembersOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	var logins []string
	for {
		members, resp, err := l.githubClient.Teams.ListTeamMembersBySlug(ctx, l.config.Organization, teamSlug, opts)
		if err != nil {
			if isPermissionError(err) {
				l.Logger.Debug("Team members fetch skipped due to permissions", "org", l.config.Organization, "team", teamSlug, "error", err)
				return nil, nil
			}
			return nil, err
		}

		for _, member := range members {
			if member == nil || member.Login == nil {
				continue
			}
			logins = append(logins, member.GetLogin())
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}

		opts.Page = resp.NextPage
	}

	return logins, nil
}
