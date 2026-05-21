package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/go-github/v71/github"
	"golang.org/x/mod/modfile"
)

const (
	dependencyEcosystemGo = "go"
	dependencySourceGoMod = "go.mod"
	dependencyPRPageSize  = 100
)

type goModuleDependency struct {
	Name    string
	Version string
	Direct  bool
}

func (l *GithubReposPlugin) GatherRepositoryDependencies(ctx context.Context, repo *github.Repository) []*RepositoryDependency {
	dependencies, err := l.gatherRepositoryDependencies(ctx, repo, nil)
	if err != nil {
		l.Logger.Warn("dependency collection callback failed", "repo", repo.GetFullName(), "error", err)
	}
	return dependencies
}

func (l *GithubReposPlugin) gatherRepositoryDependencies(ctx context.Context, repo *github.Repository, onDependency func(*RepositoryDependency) error) ([]*RepositoryDependency, error) {
	if repo == nil {
		return nil, nil
	}

	l.Logger.Debug("Fetching go.mod for dependency collection", "repo", repo.GetFullName(), "ref", repo.GetDefaultBranch())
	content, err := l.fetchGoMod(ctx, repo)
	if err != nil {
		l.Logger.Warn("failed to fetch go.mod for dependency collection", "repo", repo.GetFullName(), "error", err)
		return nil, nil
	}
	if content == "" {
		l.Logger.Debug("No go.mod content found for dependency collection", "repo", repo.GetFullName())
		return nil, nil
	}

	modDeps, err := parseGoModDirectDependencies([]byte(content))
	if err != nil {
		l.Logger.Warn("failed to parse go.mod for dependency collection", "repo", repo.GetFullName(), "error", err)
		return nil, nil
	}
	l.Logger.Debug("Parsed direct go.mod dependencies", "repo", repo.GetFullName(), "dependencies", len(modDeps))

	if len(modDeps) > l.config.dependencyHealthMaxDependencies {
		l.Logger.Debug(
			"Truncating dependency collection to configured maximum",
			"repo", repo.GetFullName(),
			"parsed_dependencies", len(modDeps),
			"max_dependencies", l.config.dependencyHealthMaxDependencies,
		)
		modDeps = modDeps[:l.config.dependencyHealthMaxDependencies]
	}

	dependencies := make([]*RepositoryDependency, 0, len(modDeps))
	repositoryFacts := make(map[string]*RepositoryDependency)
	resolved := 0
	unresolved := 0
	for _, modDep := range modDeps {
		dep := newRepositoryDependency(modDep)
		resolveDependencyRepository(dep)
		if dep.Repository.Resolved {
			resolved++
			cacheKey := dependencyRepositoryCacheKey(dep)
			if cached, ok := repositoryFacts[cacheKey]; ok {
				l.Logger.Debug(
					"Reusing cached dependency repository facts",
					"repo", repo.GetFullName(),
					"dependency", dep.Name,
					"dependency_repo", dep.Repository.URL,
				)
				copyDependencyRepositoryFacts(dep, cached)
				dependencies = append(dependencies, dep)
				if err := emitDependency(dep, onDependency); err != nil {
					return dependencies, err
				}
				continue
			}
			l.Logger.Debug(
				"Collecting dependency repository facts",
				"repo", repo.GetFullName(),
				"dependency", dep.Name,
				"dependency_repo", dep.Repository.URL,
			)
			l.collectDependencyRepositoryFacts(ctx, dep)
			repositoryFacts[cacheKey] = cloneRepositoryDependency(dep)
		} else if !l.config.dependencyHealthIncludeUnresolved {
			unresolved++
			l.Logger.Debug("Skipping unresolved dependency", "repo", repo.GetFullName(), "dependency", dep.Name)
			continue
		} else {
			unresolved++
			l.Logger.Debug("Including unresolved dependency", "repo", repo.GetFullName(), "dependency", dep.Name)
		}
		dependencies = append(dependencies, dep)
		if err := emitDependency(dep, onDependency); err != nil {
			return dependencies, err
		}
	}
	l.Logger.Debug(
		"Dependency collection finished",
		"repo", repo.GetFullName(),
		"dependencies", len(dependencies),
		"resolved", resolved,
		"unresolved", unresolved,
	)

	return dependencies, nil
}

func emitDependency(dep *RepositoryDependency, onDependency func(*RepositoryDependency) error) error {
	if onDependency == nil {
		return nil
	}
	return onDependency(dep)
}

func dependencyRepositoryCacheKey(dep *RepositoryDependency) string {
	if dep == nil || dep.Repository == nil {
		return ""
	}
	return strings.ToLower(fmt.Sprintf("%s/%s/%s", dep.Repository.Provider, dep.Repository.Owner, dep.Repository.Name))
}

func copyDependencyRepositoryFacts(target, source *RepositoryDependency) {
	if target == nil || source == nil {
		return
	}
	target.Health = cloneDependencyHealth(source.Health)
	target.SupplyChain = cloneDependencySupplyChain(source.SupplyChain)
	target.CollectionStatus = cloneDependencyCollectionStatus(source.CollectionStatus)
	if target.CollectionStatus == nil {
		target.CollectionStatus = &DependencyCollectionStatus{}
	}
	target.CollectionStatus.DependencyParsed = true
	target.CollectionStatus.RepositoryResolved = target.Repository != nil && target.Repository.Resolved
}

func cloneRepositoryDependency(dep *RepositoryDependency) *RepositoryDependency {
	if dep == nil {
		return nil
	}
	cloned := *dep
	cloned.Repository = cloneDependencyRepository(dep.Repository)
	cloned.Health = cloneDependencyHealth(dep.Health)
	cloned.SupplyChain = cloneDependencySupplyChain(dep.SupplyChain)
	cloned.CollectionStatus = cloneDependencyCollectionStatus(dep.CollectionStatus)
	return &cloned
}

func cloneDependencyRepository(repo *DependencyRepository) *DependencyRepository {
	if repo == nil {
		return nil
	}
	cloned := *repo
	return &cloned
}

func cloneDependencyHealth(health *DependencyHealth) *DependencyHealth {
	if health == nil {
		return nil
	}
	cloned := *health
	if health.LatestRelease != nil {
		release := *health.LatestRelease
		release.PublishedAt = cloneTimePtr(health.LatestRelease.PublishedAt)
		cloned.LatestRelease = &release
	}
	if health.LatestCommit != nil {
		commit := *health.LatestCommit
		commit.CommittedAt = cloneTimePtr(health.LatestCommit.CommittedAt)
		cloned.LatestCommit = &commit
	}
	if health.Workflows != nil {
		workflows := *health.Workflows
		if health.Workflows.LatestDefaultBranchRun != nil {
			run := *health.Workflows.LatestDefaultBranchRun
			run.CreatedAt = cloneTimePtr(health.Workflows.LatestDefaultBranchRun.CreatedAt)
			workflows.LatestDefaultBranchRun = &run
		}
		cloned.Workflows = &workflows
	}
	if health.PullRequests != nil {
		pullRequests := *health.PullRequests
		pullRequests.OldestOpenCreatedAt = cloneTimePtr(health.PullRequests.OldestOpenCreatedAt)
		pullRequests.MedianDaysToClose = cloneFloat64Ptr(health.PullRequests.MedianDaysToClose)
		pullRequests.MedianHoursToFirstInteraction = cloneFloat64Ptr(health.PullRequests.MedianHoursToFirstInteraction)
		cloned.PullRequests = &pullRequests
	}
	return &cloned
}

func cloneDependencySupplyChain(supplyChain *DependencySupplyChain) *DependencySupplyChain {
	if supplyChain == nil {
		return nil
	}
	cloned := *supplyChain
	if supplyChain.License != nil {
		license := *supplyChain.License
		cloned.License = &license
	}
	if supplyChain.SBOM != nil {
		sbom := *supplyChain.SBOM
		sbom.CreationInfoCreated = cloneTimePtr(supplyChain.SBOM.CreationInfoCreated)
		cloned.SBOM = &sbom
	}
	return &cloned
}

func cloneDependencyCollectionStatus(status *DependencyCollectionStatus) *DependencyCollectionStatus {
	if status == nil {
		return nil
	}
	cloned := *status
	cloned.Errors = make([]*DependencyCollectionError, 0, len(status.Errors))
	for _, collectionError := range status.Errors {
		if collectionError == nil {
			continue
		}
		copied := *collectionError
		cloned.Errors = append(cloned.Errors, &copied)
	}
	return &cloned
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func cloneFloat64Ptr(value *float64) *float64 {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func (l *GithubReposPlugin) fetchGoMod(ctx context.Context, repo *github.Repository) (string, error) {
	file, _, _, err := l.githubClient.Repositories.GetContents(
		ctx,
		repo.GetOwner().GetLogin(),
		repo.GetName(),
		dependencySourceGoMod,
		&github.RepositoryContentGetOptions{Ref: repo.GetDefaultBranch()},
	)
	if err != nil {
		if isPermissionError(err) {
			return "", nil
		}
		return "", err
	}
	if file == nil {
		return "", nil
	}
	content, err := file.GetContent()
	if err != nil {
		return "", err
	}
	return content, nil
}

func parseGoModDirectDependencies(content []byte) ([]goModuleDependency, error) {
	parsed, err := modfile.Parse(dependencySourceGoMod, content, nil)
	if err != nil {
		return nil, err
	}

	deps := make([]goModuleDependency, 0, len(parsed.Require))
	for _, req := range parsed.Require {
		if req == nil || req.Indirect {
			continue
		}
		deps = append(deps, goModuleDependency{
			Name:    req.Mod.Path,
			Version: req.Mod.Version,
			Direct:  true,
		})
	}
	return deps, nil
}

func newRepositoryDependency(modDep goModuleDependency) *RepositoryDependency {
	return &RepositoryDependency{
		Name:            modDep.Name,
		Ecosystem:       dependencyEcosystemGo,
		SourceFile:      dependencySourceGoMod,
		Direct:          modDep.Direct,
		DeclaredVersion: modDep.Version,
		Repository:      &DependencyRepository{},
		Health:          &DependencyHealth{},
		SupplyChain:     &DependencySupplyChain{},
		CollectionStatus: &DependencyCollectionStatus{
			DependencyParsed: true,
			Errors:           make([]*DependencyCollectionError, 0),
		},
	}
}

func resolveDependencyRepository(dep *RepositoryDependency) {
	owner, repo, ok := resolveGitHubModulePath(dep.Name)
	if !ok {
		return
	}
	dep.Repository = &DependencyRepository{
		Provider: "github",
		Owner:    owner,
		Name:     repo,
		URL:      fmt.Sprintf("https://github.com/%s/%s", owner, repo),
		Resolved: true,
	}
	dep.CollectionStatus.RepositoryResolved = true
}

func resolveGitHubModulePath(modulePath string) (string, string, bool) {
	parts := strings.Split(modulePath, "/")
	if len(parts) < 3 || parts[0] != "github.com" || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func (l *GithubReposPlugin) collectDependencyRepositoryFacts(ctx context.Context, dep *RepositoryDependency) {
	owner := dep.Repository.Owner
	name := dep.Repository.Name

	repo, _, err := l.githubClient.Repositories.Get(ctx, owner, name)
	if err != nil {
		l.recordDependencyCollectionError(dep, "repository", err)
		return
	}

	dep.Health.RepositoryArchived = repo.GetArchived()
	dep.CollectionStatus.HealthCollected = true

	l.collectDependencyRelease(ctx, dep)
	l.collectDependencyCommit(ctx, dep, repo.GetDefaultBranch())
	l.collectDependencyWorkflows(ctx, dep, repo.GetDefaultBranch())
	l.collectDependencyPullRequests(ctx, dep)
	l.collectDependencyLicense(ctx, dep)
	if l.config.dependencyHealthCollectSBOM {
		l.collectDependencySBOM(ctx, dep)
	}
}

func (l *GithubReposPlugin) collectDependencyRelease(ctx context.Context, dep *RepositoryDependency) {
	release, resp, err := l.githubClient.Repositories.GetLatestRelease(ctx, dep.Repository.Owner, dep.Repository.Name)
	if err != nil {
		if resp != nil && resp.Response != nil && resp.StatusCode == 404 {
			return
		}
		l.recordDependencyCollectionError(dep, "release", err)
		return
	}
	if release == nil {
		return
	}
	dep.Health.LatestRelease = &DependencyRelease{
		Tag:         release.GetTagName(),
		PublishedAt: githubTimestampTime(release.PublishedAt),
	}
}

func (l *GithubReposPlugin) collectDependencyCommit(ctx context.Context, dep *RepositoryDependency, defaultBranch string) {
	commits, _, err := l.githubClient.Repositories.ListCommits(ctx, dep.Repository.Owner, dep.Repository.Name, &github.CommitsListOptions{
		SHA:         defaultBranch,
		ListOptions: github.ListOptions{PerPage: 1},
	})
	if err != nil {
		l.recordDependencyCollectionError(dep, "commit", err)
		return
	}
	if len(commits) == 0 || commits[0] == nil {
		return
	}
	dep.Health.LatestCommit = &DependencyCommit{
		SHA: commits[0].GetSHA(),
	}
	if commits[0].Commit != nil && commits[0].Commit.Committer != nil {
		dep.Health.LatestCommit.CommittedAt = githubTimestampTime(commits[0].Commit.Committer.Date)
	}
}

func (l *GithubReposPlugin) collectDependencyWorkflows(ctx context.Context, dep *RepositoryDependency, defaultBranch string) {
	workflows, _, err := l.githubClient.Actions.ListWorkflows(ctx, dep.Repository.Owner, dep.Repository.Name, nil)
	if err != nil {
		l.recordDependencyCollectionError(dep, "workflows", err)
		return
	}
	summary := &DependencyWorkflowSummary{}
	if workflows != nil {
		summary.Count = len(workflows.Workflows)
	}

	runs, _, err := l.githubClient.Actions.ListRepositoryWorkflowRuns(ctx, dep.Repository.Owner, dep.Repository.Name, &github.ListWorkflowRunsOptions{
		Branch:      defaultBranch,
		ListOptions: github.ListOptions{PerPage: 1},
	})
	if err != nil {
		l.recordDependencyCollectionError(dep, "workflow_runs", err)
		dep.Health.Workflows = summary
		return
	}
	if runs != nil && len(runs.WorkflowRuns) > 0 && runs.WorkflowRuns[0] != nil {
		run := runs.WorkflowRuns[0]
		summary.LatestDefaultBranchRun = &DependencyWorkflowRun{
			Status:     run.GetStatus(),
			Conclusion: run.GetConclusion(),
			CreatedAt:  githubTimestampTime(run.CreatedAt),
		}
	}
	dep.Health.Workflows = summary
}

func (l *GithubReposPlugin) collectDependencyLicense(ctx context.Context, dep *RepositoryDependency) {
	dep.SupplyChain.License = &DependencyLicenseSummary{}
	license, resp, err := l.githubClient.Repositories.License(ctx, dep.Repository.Owner, dep.Repository.Name)
	if err != nil {
		if resp != nil && resp.Response != nil && resp.StatusCode == 404 {
			dep.SupplyChain.License.Collected = true
			dep.CollectionStatus.LicenseCollected = true
			return
		}
		l.recordDependencyCollectionError(dep, "license", err)
		return
	}
	dep.SupplyChain.License.Collected = true
	dep.CollectionStatus.LicenseCollected = true
	if license == nil || license.License == nil {
		return
	}
	dep.SupplyChain.License.SPDXID = license.License.GetSPDXID()
	dep.SupplyChain.License.Name = license.License.GetName()
	dep.SupplyChain.License.URL = license.License.GetURL()
}

func (l *GithubReposPlugin) collectDependencySBOM(ctx context.Context, dep *RepositoryDependency) {
	dep.SupplyChain.SBOM = &DependencySBOMSummary{}
	sbom, _, err := l.githubClient.DependencyGraph.GetSBOM(ctx, dep.Repository.Owner, dep.Repository.Name)
	if err != nil {
		l.recordDependencyCollectionError(dep, "sbom", err)
		return
	}
	dep.SupplyChain.SBOM.Collected = true
	dep.CollectionStatus.SBOMCollected = true
	if sbom == nil || sbom.SBOM == nil {
		return
	}
	info := sbom.SBOM
	dep.SupplyChain.SBOM.Available = true
	dep.SupplyChain.SBOM.PackageCount = len(info.Packages)
	dep.SupplyChain.SBOM.SPDXID = info.GetSPDXID()
	dep.SupplyChain.SBOM.SPDXVersion = info.GetSPDXVersion()
	if info.CreationInfo != nil {
		dep.SupplyChain.SBOM.CreationInfoCreated = githubTimestampTime(info.CreationInfo.Created)
	}
}

func (l *GithubReposPlugin) collectDependencyPullRequests(ctx context.Context, dep *RepositoryDependency) {
	stats := &DependencyPullRequestStats{}

	openPRs, err := l.listPullRequestIssues(ctx, dep.Repository.Owner, dep.Repository.Name, "open", time.Time{})
	if err != nil {
		l.recordDependencyCollectionError(dep, "pull_requests_open", err)
		dep.Health.PullRequests = stats
		return
	}
	stats.OpenCount = len(openPRs)
	for _, pr := range openPRs {
		created := githubTimestampTime(pr.CreatedAt)
		if created == nil {
			continue
		}
		if stats.OldestOpenCreatedAt == nil || created.Before(*stats.OldestOpenCreatedAt) {
			stats.OldestOpenCreatedAt = created
		}
	}

	since := time.Now().AddDate(0, 0, -l.config.dependencyHealthClosedPRLookbackDays)
	closedPRs, err := l.listPullRequestIssues(ctx, dep.Repository.Owner, dep.Repository.Name, "closed", since)
	if err != nil {
		l.recordDependencyCollectionError(dep, "pull_requests_closed", err)
		dep.Health.PullRequests = stats
		return
	}
	stats.RecentClosedCount = len(closedPRs)
	stats.MedianDaysToClose = medianDaysToClose(closedPRs)
	dep.Health.PullRequests = stats
	stats.MedianHoursToFirstInteraction = l.medianHoursToFirstInteraction(ctx, dep, closedPRs)
}

func (l *GithubReposPlugin) listPullRequestIssues(ctx context.Context, owner, repo, state string, since time.Time) ([]*github.Issue, error) {
	opts := &github.IssueListByRepoOptions{
		State:       state,
		ListOptions: github.ListOptions{PerPage: dependencyPRPageSize, Page: 1},
	}
	if !since.IsZero() {
		opts.Since = since
	}

	issues, _, err := l.githubClient.Issues.ListByRepo(ctx, owner, repo, opts)
	if err != nil {
		return nil, err
	}
	prs := make([]*github.Issue, 0, len(issues))
	for _, issue := range issues {
		if issue == nil || !issue.IsPullRequest() {
			continue
		}
		prs = append(prs, issue)
	}
	return prs, nil
}

func medianDaysToClose(prs []*github.Issue) *float64 {
	values := make([]float64, 0, len(prs))
	for _, pr := range prs {
		created := githubTimestampTime(pr.CreatedAt)
		closed := githubTimestampTime(pr.ClosedAt)
		if created == nil || closed == nil || closed.Before(*created) {
			continue
		}
		values = append(values, closed.Sub(*created).Hours()/24)
	}
	return medianFloat64(values)
}

func (l *GithubReposPlugin) medianHoursToFirstInteraction(ctx context.Context, dep *RepositoryDependency, prs []*github.Issue) *float64 {
	limit := l.config.dependencyHealthPRInteractionSampleSize
	if limit > len(prs) {
		limit = len(prs)
	}
	values := make([]float64, 0, limit)
	for i := 0; i < limit; i++ {
		pr := prs[i]
		if pr == nil {
			continue
		}
		created := githubTimestampTime(pr.CreatedAt)
		if created == nil {
			continue
		}
		first, err := l.firstPullRequestInteraction(ctx, dep.Repository.Owner, dep.Repository.Name, pr.GetNumber(), *created)
		if err != nil {
			l.recordDependencyCollectionError(dep, "pull_request_interactions", err)
			continue
		}
		if first == nil {
			continue
		}
		values = append(values, first.Sub(*created).Hours())
	}
	if dep.Health.PullRequests != nil {
		dep.Health.PullRequests.FirstInteractionSampledPullRequests = limit
	}
	return medianFloat64(values)
}

func (l *GithubReposPlugin) firstPullRequestInteraction(ctx context.Context, owner, repo string, number int, created time.Time) (*time.Time, error) {
	var first *time.Time
	comments, _, err := l.githubClient.Issues.ListComments(ctx, owner, repo, number, &github.IssueListCommentsOptions{
		Sort:        github.Ptr("created"),
		Direction:   github.Ptr("asc"),
		ListOptions: github.ListOptions{PerPage: 100},
	})
	if err != nil {
		return nil, err
	}
	for _, comment := range comments {
		ts := githubTimestampTime(comment.CreatedAt)
		if ts == nil || !ts.After(created) {
			continue
		}
		if first == nil || ts.Before(*first) {
			first = ts
		}
	}

	reviews, _, err := l.githubClient.PullRequests.ListReviews(ctx, owner, repo, number, &github.ListOptions{PerPage: 100})
	if err != nil {
		return nil, err
	}
	for _, review := range reviews {
		ts := githubTimestampTime(review.SubmittedAt)
		if ts == nil || !ts.After(created) {
			continue
		}
		if first == nil || ts.Before(*first) {
			first = ts
		}
	}
	return first, nil
}

func medianFloat64(values []float64) *float64 {
	if len(values) == 0 {
		return nil
	}
	sort.Float64s(values)
	mid := len(values) / 2
	if len(values)%2 == 1 {
		return &values[mid]
	}
	median := (values[mid-1] + values[mid]) / 2
	return &median
}

func githubTimestampTime(ts *github.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.Time
	return &t
}

func (l *GithubReposPlugin) recordDependencyCollectionError(dep *RepositoryDependency, scope string, err error) {
	if dep == nil || dep.CollectionStatus == nil || err == nil {
		return
	}
	dep.CollectionStatus.Errors = append(dep.CollectionStatus.Errors, &DependencyCollectionError{
		Scope:   scope,
		Message: err.Error(),
	})
	if l != nil && l.Logger != nil {
		l.Logger.Warn("dependency health collection partially failed", "dependency", dep.Name, "scope", scope, "error", err)
	}
}
