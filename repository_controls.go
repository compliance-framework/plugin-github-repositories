package main

import (
	"context"
	"sync"

	"github.com/google/go-github/v71/github"
)

const maxEnvironmentDetailConcurrency = 5

func (l *GithubReposPlugin) GatherRepositoryCollaborators(ctx context.Context, repo *github.Repository) ([]*RepositoryCollaborator, error) {
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()
	opts := &github.ListCollaboratorsOptions{
		Affiliation: "direct",
		ListOptions: github.ListOptions{PerPage: 100, Page: 1},
	}

	var collaborators []*RepositoryCollaborator
	for {
		users, resp, err := l.githubClient.Repositories.ListCollaborators(ctx, owner, name, opts)
		if err != nil {
			if isPermissionError(err) {
				l.Logger.Debug("Repository collaborators fetch skipped due to permissions", "repo", repo.GetFullName(), "error", err)
				return nil, nil
			}
			return nil, err
		}

		for _, user := range users {
			if user == nil {
				continue
			}
			collaborators = append(collaborators, &RepositoryCollaborator{
				Login:       user.GetLogin(),
				RoleName:    user.GetRoleName(),
				Permissions: copyPermissions(user.GetPermissions()),
			})
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return collaborators, nil
}

func (l *GithubReposPlugin) GatherRepositoryTeams(ctx context.Context, repo *github.Repository, orgTeams []*OrgTeam) ([]*RepositoryTeam, error) {
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()
	opts := &github.ListOptions{PerPage: 100, Page: 1}

	var teams []*RepositoryTeam
	for {
		ghTeams, resp, err := l.githubClient.Repositories.ListTeams(ctx, owner, name, opts)
		if err != nil {
			if isPermissionError(err) {
				l.Logger.Debug("Repository teams fetch skipped due to permissions", "repo", repo.GetFullName(), "error", err)
				return nil, nil
			}
			return nil, err
		}

		for _, team := range ghTeams {
			if team == nil {
				continue
			}
			teams = append(teams, &RepositoryTeam{
				ID:          team.GetID(),
				Name:        team.GetName(),
				Slug:        team.GetSlug(),
				Permission:  team.GetPermission(),
				Permissions: copyPermissions(team.GetPermissions()),
				Members:     membersForOrgTeam(orgTeams, team.GetSlug()),
			})
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return teams, nil
}

func (l *GithubReposPlugin) GatherRepositoryEnvironments(ctx context.Context, repo *github.Repository) ([]*RepositoryEnvironment, error) {
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()
	opts := &github.EnvironmentListOptions{ListOptions: github.ListOptions{PerPage: 100, Page: 1}}

	var environments []*RepositoryEnvironment
	for {
		envResp, resp, err := l.githubClient.Repositories.ListEnvironments(ctx, owner, name, opts)
		if err != nil {
			if isPermissionError(err) {
				l.Logger.Debug("Repository environments fetch skipped due to permissions", "repo", repo.GetFullName(), "error", err)
				return nil, nil
			}
			return nil, err
		}

		if envResp != nil {
			environments = append(environments, l.repositoryEnvironmentsFromGitHub(ctx, repo, envResp.Environments)...)
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return environments, nil
}

func (l *GithubReposPlugin) GatherEffectiveBranchRules(ctx context.Context, repo *github.Repository, branches []string) (map[string]*BranchRuleEvidence, error) {
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()
	targets := map[string]struct{}{}
	for _, branch := range branches {
		if branch != "" {
			targets[branch] = struct{}{}
		}
	}
	if def := repo.GetDefaultBranch(); def != "" {
		targets[def] = struct{}{}
	}

	evidence := make(map[string]*BranchRuleEvidence, len(targets))
	for branch := range targets {
		rules, _, err := l.githubClient.Repositories.GetRulesForBranch(ctx, owner, name, branch)
		if err != nil {
			if isPermissionError(err) {
				l.Logger.Debug("Effective branch rules fetch skipped due to permissions", "repo", repo.GetFullName(), "branch", branch, "error", err)
				return nil, nil
			}
			l.Logger.Trace("Effective branch rules fetch failed", "repo", repo.GetFullName(), "branch", branch, "error", err)
			continue
		}
		evidence[branch] = branchRuleEvidenceFromGitHub(rules)
	}

	return evidence, nil
}

func (l *GithubReposPlugin) repositoryEnvironmentsFromGitHub(ctx context.Context, repo *github.Repository, environments []*github.Environment) []*RepositoryEnvironment {
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()
	details := make([]*github.Environment, len(environments))

	var wg sync.WaitGroup
	jobs := make(chan int)
	workers := min(maxEnvironmentDetailConcurrency, len(environments))
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				env := environments[i]
				if env == nil {
					continue
				}

				detail, _, err := l.githubClient.Repositories.GetEnvironment(ctx, owner, name, env.GetName())
				if err != nil {
					l.Logger.Trace("Repository environment detail fetch failed", "repo", repo.GetFullName(), "environment", env.GetName(), "error", err)
					detail = env
				}
				details[i] = detail
			}
		}()
	}

	for i, env := range environments {
		if env == nil {
			continue
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	out := make([]*RepositoryEnvironment, 0, len(details))
	for _, detail := range details {
		env := repositoryEnvironmentFromGitHub(detail)
		if env == nil {
			continue
		}
		out = append(out, env)
	}
	return out
}

func branchRuleEvidenceFromGitHub(rules *github.BranchRules) *BranchRuleEvidence {
	evidence := &BranchRuleEvidence{}
	if rules == nil {
		return evidence
	}

	evidence.RequiredSignatures = len(rules.RequiredSignatures) > 0
	for _, rule := range rules.RequiredDeployments {
		if rule == nil {
			continue
		}
		evidence.RequiredDeployments = append(evidence.RequiredDeployments, rule.Parameters.RequiredDeploymentEnvironments...)
	}
	for _, rule := range rules.CodeScanning {
		if rule == nil {
			continue
		}
		for _, tool := range rule.Parameters.CodeScanningTools {
			if tool == nil {
				continue
			}
			evidence.CodeScanningTools = append(evidence.CodeScanningTools, tool.Tool)
		}
	}

	return evidence
}

func repositoryEnvironmentFromGitHub(env *github.Environment) *RepositoryEnvironment {
	if env == nil {
		return nil
	}

	out := &RepositoryEnvironment{
		ID:              env.GetID(),
		Name:            env.GetName(),
		URL:             env.GetURL(),
		HTMLURL:         env.GetHTMLURL(),
		WaitTimer:       env.GetWaitTimer(),
		CanAdminsBypass: env.GetCanAdminsBypass(),
		Reviewers:       reviewersFromEnvReviewers(env.Reviewers),
	}
	if env.DeploymentBranchPolicy != nil {
		out.DeploymentBranchPolicy = &EnvironmentBranchPolicy{
			ProtectedBranches:    env.DeploymentBranchPolicy.GetProtectedBranches(),
			CustomBranchPolicies: env.DeploymentBranchPolicy.GetCustomBranchPolicies(),
		}
	}
	for _, rule := range env.ProtectionRules {
		protectionRule := protectionRuleFromGitHub(rule)
		if protectionRule == nil {
			continue
		}
		out.ProtectionRules = append(out.ProtectionRules, protectionRule)
	}

	return out
}

func protectionRuleFromGitHub(rule *github.ProtectionRule) *EnvironmentProtectionRule {
	if rule == nil {
		return nil
	}

	out := &EnvironmentProtectionRule{
		ID:                rule.GetID(),
		Type:              rule.GetType(),
		WaitTimer:         rule.GetWaitTimer(),
		PreventSelfReview: rule.GetPreventSelfReview(),
	}
	for _, reviewer := range rule.Reviewers {
		requiredReviewer := reviewerFromRequiredReviewer(reviewer)
		if requiredReviewer == nil {
			continue
		}
		out.Reviewers = append(out.Reviewers, requiredReviewer)
	}

	return out
}

func reviewersFromEnvReviewers(reviewers []*github.EnvReviewers) []*EnvironmentReviewer {
	out := make([]*EnvironmentReviewer, 0, len(reviewers))
	for _, reviewer := range reviewers {
		if reviewer == nil {
			continue
		}
		out = append(out, &EnvironmentReviewer{
			Type: reviewer.GetType(),
			ID:   reviewer.GetID(),
		})
	}
	return out
}

func reviewerFromRequiredReviewer(reviewer *github.RequiredReviewer) *EnvironmentReviewer {
	if reviewer == nil {
		return nil
	}

	out := &EnvironmentReviewer{Type: reviewer.GetType()}
	switch r := reviewer.Reviewer.(type) {
	case *github.User:
		out.ID = r.GetID()
		out.Login = r.GetLogin()
		out.Name = r.GetName()
	case github.User:
		out.ID = r.GetID()
		out.Login = r.GetLogin()
		out.Name = r.GetName()
	case *github.Team:
		out.ID = r.GetID()
		out.Slug = r.GetSlug()
		out.Name = r.GetName()
	case github.Team:
		out.ID = r.GetID()
		out.Slug = r.GetSlug()
		out.Name = r.GetName()
	}
	return out
}

func membersForOrgTeam(orgTeams []*OrgTeam, slug string) []string {
	for _, team := range orgTeams {
		if team != nil && team.Slug == slug {
			return append([]string{}, team.Members...)
		}
	}
	return nil
}

func copyPermissions(in map[string]bool) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
