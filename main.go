package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/mitchellh/mapstructure"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

// Validator is implemented by configuration values that can validate themselves.
type Validator interface {
	Validate() error
}

// PluginConfig contains user-provided and parsed runtime configuration for the plugin.
type PluginConfig struct {
	Token                                   string `mapstructure:"token"`
	Organization                            string `mapstructure:"organization"`
	IncludedRepositories                    string `mapstructure:"included_repositories"`
	ExcludedRepositories                    string `mapstructure:"excluded_repositories"`
	DeploymentLookbackDays                  string `mapstructure:"deployment_lookback_days"`   // Number of days to look back for deployments (default: 90)
	OnlyActiveDeployments                   string `mapstructure:"only_active_deployments"`    // Only fetch deployments that are still active (not superseded) (default: false)
	IncludeFailedDeployments                string `mapstructure:"include_failed_deployments"` // Include deployments with failure/error states (default: false)
	DependencyHealthEnabled                 string `mapstructure:"dependency_health_enabled"`
	DependencyHealthMaxDependencies         string `mapstructure:"dependency_health_max_dependencies"`
	DependencyHealthClosedPRLookbackDays    string `mapstructure:"dependency_health_closed_pr_lookback_days"`
	DependencyHealthIncludeUnresolved       string `mapstructure:"dependency_health_include_unresolved"`
	DependencyHealthCollectSBOM             string `mapstructure:"dependency_health_collect_sbom"`
	DependencyHealthPRInteractionSampleSize string `mapstructure:"dependency_health_pr_interaction_sample_size"`
	PolicyInput                             string `mapstructure:"policy_input"`

	// Parsed values (set during Configure)
	policyData                              map[string]interface{}
	deploymentLookbackDays                  int
	onlyActiveDeployments                   bool
	includeFailedDeployments                bool
	dependencyHealthEnabled                 bool
	dependencyHealthMaxDependencies         int
	dependencyHealthClosedPRLookbackDays    int
	dependencyHealthIncludeUnresolved       bool
	dependencyHealthCollectSBOM             bool
	dependencyHealthPRInteractionSampleSize int
}

// Validate checks required configuration fields and mutually exclusive repository filters.
func (c *PluginConfig) Validate() error {
	if c.Token == "" {
		return fmt.Errorf("token is required")
	}
	if c.Organization == "" {
		return fmt.Errorf("organization is required")
	}

	// As IncludedRepositories and ExcludedRepositories are mutually exclusive
	// check if both are set and error back if they are
	if c.IncludedRepositories != "" && c.ExcludedRepositories != "" {
		return fmt.Errorf("only one of included_repositories or excluded_repositories may be set")
	}
	return nil
}

func (c *PluginConfig) parseDeploymentConfig() error {
	// Parse deployment lookback days (default: 90)
	if c.DeploymentLookbackDays == "" {
		c.deploymentLookbackDays = 90
	} else {
		days, err := strconv.Atoi(c.DeploymentLookbackDays)
		if err != nil {
			return fmt.Errorf("invalid deployment_lookback_days: %w", err)
		}
		c.deploymentLookbackDays = days
	}

	// Parse only active deployments (default: false)
	if c.OnlyActiveDeployments == "" {
		c.onlyActiveDeployments = false
	} else {
		active, err := strconv.ParseBool(c.OnlyActiveDeployments)
		if err != nil {
			return fmt.Errorf("invalid only_active_deployments: %w", err)
		}
		c.onlyActiveDeployments = active
	}

	// Parse include failed deployments (default: false)
	if c.IncludeFailedDeployments == "" {
		c.includeFailedDeployments = false
	} else {
		include, err := strconv.ParseBool(c.IncludeFailedDeployments)
		if err != nil {
			return fmt.Errorf("invalid include_failed_deployments: %w", err)
		}
		c.includeFailedDeployments = include
	}

	return nil
}

func (c *PluginConfig) parseDependencyHealthConfig() error {
	var err error
	c.dependencyHealthEnabled, err = parseBoolConfig(c.DependencyHealthEnabled, false, "dependency_health_enabled")
	if err != nil {
		return err
	}
	c.dependencyHealthMaxDependencies, err = parsePositiveIntConfig(c.DependencyHealthMaxDependencies, 50, "dependency_health_max_dependencies")
	if err != nil {
		return err
	}
	c.dependencyHealthClosedPRLookbackDays, err = parsePositiveIntConfig(c.DependencyHealthClosedPRLookbackDays, 180, "dependency_health_closed_pr_lookback_days")
	if err != nil {
		return err
	}
	c.dependencyHealthIncludeUnresolved, err = parseBoolConfig(c.DependencyHealthIncludeUnresolved, true, "dependency_health_include_unresolved")
	if err != nil {
		return err
	}
	c.dependencyHealthCollectSBOM, err = parseBoolConfig(c.DependencyHealthCollectSBOM, true, "dependency_health_collect_sbom")
	if err != nil {
		return err
	}
	c.dependencyHealthPRInteractionSampleSize, err = parsePositiveIntConfig(c.DependencyHealthPRInteractionSampleSize, 20, "dependency_health_pr_interaction_sample_size")
	if err != nil {
		return err
	}
	return nil
}

func (c *PluginConfig) parseLegacyPolicyInput() (map[string]interface{}, error) {
	if c.PolicyInput == "" {
		return map[string]interface{}{}, nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(c.PolicyInput), &result); err != nil {
		return nil, fmt.Errorf("invalid policy_input JSON: %w", err)
	}
	return result, nil
}

func parseBoolConfig(value string, defaultValue bool, name string) (bool, error) {
	if value == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid %s: %w", name, err)
	}
	return parsed, nil
}

func parsePositiveIntConfig(value string, defaultValue int, name string) (int, error) {
	if value == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", name, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("invalid %s: must be greater than 0", name)
	}
	return parsed, nil
}

// DeploymentWithStatuses pairs a deployment with its observed deployment statuses.
type DeploymentWithStatuses struct {
	Deployment *github.Deployment         `json:"deployment"`
	Statuses   []*github.DeploymentStatus `json:"statuses"`
}

// SaturatedRepository contains all repository facts passed to repository policies.
type SaturatedRepository struct {
	Settings     *github.Repository    `json:"settings"`
	Workflows    []*github.Workflow    `json:"workflows"`
	WorkflowRuns []*github.WorkflowRun `json:"workflow_runs"`
	// ProtectedBranches is the list of protected branches in the repository
	ProtectedBranches []string `json:"protected_branches"`
	// BranchProtectionRules maps branch name -> full branch protection configuration
	BranchProtectionRules map[string]*github.Protection `json:"branch_protection_rules"`
	// RequiredStatusChecks maps branch name -> required status checks configuration
	RequiredStatusChecks map[string]*github.RequiredStatusChecks `json:"required_status_checks"`
	SBOM                 *github.SBOM                            `json:"sbom"`
	LastRelease          *github.RepositoryRelease               `json:"last_release"`
	OpenPullRequests     []*OpenPullRequest                      `json:"pull_requests"`
	CodeOwners           *github.RepositoryContent               `json:"code_owners"`
	OrgTeams             []*OrgTeam                              `json:"org_teams"`
	Deployments          []*DeploymentWithStatuses               `json:"deployments"`
	FailedDeployments    []*DeploymentWithStatuses               `json:"failed_deployments"`
	Collaborators        []*RepositoryCollaborator               `json:"collaborators"`
	RepositoryTeams      []*RepositoryTeam                       `json:"repository_teams"`
	Environments         []*RepositoryEnvironment                `json:"environments"`
	EffectiveBranchRules map[string]*BranchRuleEvidence          `json:"effective_branch_rules"`
	PolicyData           map[string]interface{}                  `json:"policy_data"`
	PolicyInput          map[string]interface{}                  `json:"policy_input"`
}

// GithubReposPlugin implements the CCF runner interface for GitHub repository evidence.
type GithubReposPlugin struct {
	Logger hclog.Logger

	config        *PluginConfig
	githubClient  *github.Client
	graphqlClient *githubv4.Client
}

// Configure validates configuration and initializes GitHub REST and GraphQL clients.
func (l *GithubReposPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.Logger.Info("Configuring GitHub Repositories Plugin")
	config := &PluginConfig{policyData: map[string]interface{}{}}

	if err := mapstructure.Decode(req.Config, config); err != nil {
		l.Logger.Error("Error decoding config", "error", err)
		return nil, err
	}

	if err := config.Validate(); err != nil {
		l.Logger.Error("Error validating config", "error", err)
		return nil, err
	}

	// Parse deployment configuration from strings
	if err := config.parseDeploymentConfig(); err != nil {
		l.Logger.Error("Error parsing deployment config", "error", err)
		return nil, err
	}
	if err := config.parseDependencyHealthConfig(); err != nil {
		l.Logger.Error("Error parsing dependency health config", "error", err)
		return nil, err
	}
	if req.GetPolicyData() != nil {
		config.policyData = req.GetPolicyData().AsMap()
	} else {
		legacyPolicyInput, err := config.parseLegacyPolicyInput()
		if err != nil {
			l.Logger.Error("Error parsing legacy policy input", "error", err)
			return nil, err
		}
		config.policyData = legacyPolicyInput
	}
	l.Logger.Debug(
		"Policy data parsed",
		"policy_data_keys", mapKeys(config.policyData),
		"policy_data_count", len(config.policyData),
	)
	l.Logger.Debug(
		"Dependency health config parsed",
		"enabled", config.dependencyHealthEnabled,
		"max_dependencies", config.dependencyHealthMaxDependencies,
		"closed_pr_lookback_days", config.dependencyHealthClosedPRLookbackDays,
		"include_unresolved", config.dependencyHealthIncludeUnresolved,
		"collect_sbom", config.dependencyHealthCollectSBOM,
		"pr_interaction_sample_size", config.dependencyHealthPRInteractionSampleSize,
	)

	l.config = config
	httpClient := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: config.Token,
	}))
	l.githubClient = github.NewClient(httpClient)
	l.graphqlClient = githubv4.NewClient(httpClient)

	return &proto.ConfigureResponse{}, nil
}

// Init registers subject templates and policy-derived risks for this plugin.
func (l *GithubReposPlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	ctx := context.Background()

	subjectTemplates := []*proto.SubjectTemplate{
		{
			Name:                "github-repository",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       "GitHub Repository: {{ .repository }}",
			DescriptionTemplate: "GitHub repository {{ .repository }} in organization {{ .organization }}",
			PurposeTemplate:     "Represents a GitHub repository being monitored for compliance",
			IdentityLabelKeys:   []string{"repository", "organization"},
			// Only label needed is the configuration from the agent
			SelectorLabels: []*proto.SubjectLabelSelector{},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "repository", Description: "The name of the GitHub repository"},
				{Key: "organization", Description: "The GitHub organization owning the repository"},
			},
		},
	}

	return runner.InitWithSubjectsAndRisksFromPolicies(ctx, l.Logger, req, apiHelper, subjectTemplates)
}

// Eval gathers repository evidence, evaluates repository policies, and evaluates dependency policies when configured.
func (l *GithubReposPlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	policyRequest := requestWithDefaultPolicyBehavior(req)
	repositoryPolicyPaths := policyRequest.PolicyPathsForBehavior(policyBehaviorRepository)
	dependencyPolicyPaths := policyRequest.PolicyPathsForBehavior(policyBehaviorDependency)
	l.Logger.Debug(
		"Resolved policy paths by behavior",
		"policy_paths", policyRequest.GetPolicyPaths(),
		"repository_policy_paths", repositoryPolicyPaths,
		"dependency_policy_paths", dependencyPolicyPaths,
	)
	repochan, errchan := l.FetchRepositories(ctx, req)
	done := false

	orgTeams, err := l.GatherOrgTeams(ctx)
	if err != nil {
		l.Logger.Error("Error gathering organization teams", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	for !done {
		select {
		case err, ok := <-errchan:
			if !ok {
				done = true
				continue
			}
			l.Logger.Error("Error fetching repositories", "error", err)
			return &proto.EvalResponse{
				Status: proto.ExecutionStatus_FAILURE,
			}, err
		case repo, ok := <-repochan:
			if !ok {
				done = true
				continue
			}
			workflows, err := l.GatherConfiguredWorkflows(ctx, repo)
			if err != nil {
				l.Logger.Error("Error gathering workflows", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			workflowRuns, err := l.GatherWorkflowRuns(ctx, repo)
			if err != nil {
				l.Logger.Error("Error gathering workflow runs", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			// Fetch protected branches and required status checks
			branches, err := l.ListProtectedBranches(ctx, repo)
			if err != nil {
				l.Logger.Error("Error listing protected branches", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
			branchNames := make([]string, 0, len(branches))
			branchProtectionRules := make(map[string]*github.Protection)
			requiredChecks := make(map[string]*github.RequiredStatusChecks)
			for _, b := range branches {
				if b == nil || b.Name == nil {
					continue
				}
				name := b.GetName()
				branchNames = append(branchNames, name)
				protection, checks, err := l.GetBranchProtectionAndRequiredStatusCheck(ctx, repo, name)
				if err != nil {
					l.Logger.Trace("Branch protection fetch failed", "repo", repo.GetFullName(), "branch", name, "error", err)
					continue
				}
				if protection != nil {
					branchProtectionRules[name] = protection
				}
				if checks != nil {
					requiredChecks[name] = checks
				}
			}
			// Fallback to default branch if none collected
			if len(requiredChecks) == 0 {
				if def := repo.GetDefaultBranch(); def != "" {
					if protection, checks, err := l.GetBranchProtectionAndRequiredStatusCheck(ctx, repo, def); err == nil {
						if protection != nil {
							branchProtectionRules[def] = protection
						}
						if checks != nil {
							requiredChecks[def] = checks
						}
					} else {
						l.Logger.Trace("Default branch protection fetch failed", "repo", repo.GetFullName(), "branch", def, "error", err)
					}
				}
			}

			sbom, err := l.GatherSBOM(ctx, repo)
			if err != nil {
				l.Logger.Error("Error gathering SBOM", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			pullRequests, err := l.GatherOpenPullRequests(ctx, repo)
			if err != nil {
				l.Logger.Error("error gathering pull requests", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
			openPullRequests, err := l.GatherReviewsAndComments(ctx, repo, pullRequests)
			if err != nil {
				l.Logger.Error("error gathering pull request reviews/comments", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
			release, err := l.FecthLatestRelease(ctx, repo)
			if err != nil {
				l.Logger.Error("error gathering latest release", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
			codeOwners, err := l.FetchCodeOwners(ctx, repo)
			if err != nil {
				l.Logger.Error("error gathering CODEOWNERS", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
			allDeployments, err := l.fetchDeploymentsWithStatuses(ctx, repo)
			if err != nil {
				l.Logger.Error("error gathering deployments", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
			deployments := l.filterDeployments(allDeployments)
			failedDeployments := deploymentsWithFailures(allDeployments)
			collaborators, err := l.GatherRepositoryCollaborators(ctx, repo)
			if err != nil {
				l.Logger.Error("error gathering repository collaborators", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
			repositoryTeams, err := l.GatherRepositoryTeams(ctx, repo, orgTeams)
			if err != nil {
				l.Logger.Error("error gathering repository teams", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
			environments, err := l.GatherRepositoryEnvironments(ctx, repo)
			if err != nil {
				l.Logger.Error("error gathering repository environments", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
			effectiveBranchRules, err := l.GatherEffectiveBranchRules(ctx, repo, branchNames)
			if err != nil {
				l.Logger.Error("error gathering effective branch rules", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
			data := &SaturatedRepository{
				Settings:              repo,
				Workflows:             workflows,
				WorkflowRuns:          workflowRuns,
				ProtectedBranches:     branchNames,
				BranchProtectionRules: branchProtectionRules,
				RequiredStatusChecks:  requiredChecks,
				LastRelease:           release,
				SBOM:                  sbom,
				OpenPullRequests:      openPullRequests,
				CodeOwners:            codeOwners,
				OrgTeams:              orgTeams,
				Deployments:           deployments,
				FailedDeployments:     failedDeployments,
				Collaborators:         collaborators,
				RepositoryTeams:       repositoryTeams,
				Environments:          environments,
				EffectiveBranchRules:  effectiveBranchRules,
				PolicyData:            l.config.policyData,
				PolicyInput:           l.config.policyData,
			}

			if len(repositoryPolicyPaths) > 0 {
				evidences, err := l.EvaluatePolicies(ctx, data, nil, repositoryPolicyPaths, nil)
				if err != nil {
					l.Logger.Error("Error evaluating repository policies", "error", err)
					return &proto.EvalResponse{
						Status: proto.ExecutionStatus_FAILURE,
					}, err
				}
				if err := apiHelper.CreateEvidence(ctx, evidences); err != nil {
					l.Logger.Error("Error creating repository evidence", "error", err)
					return &proto.EvalResponse{
						Status: proto.ExecutionStatus_FAILURE,
					}, err
				}
			}

			if len(dependencyPolicyPaths) == 0 {
				continue
			}
			if !l.config.dependencyHealthEnabled {
				l.Logger.Warn(
					"Dependency policy paths were provided, but dependency health collection is disabled",
					"repo", repo.GetFullName(),
					"dependency_policy_paths", dependencyPolicyPaths,
				)
				continue
			}

			l.Logger.Debug("Collecting repository dependencies", "repo", repo.GetFullName())
			dependencies, err := l.gatherRepositoryDependencies(ctx, repo, func(*RepositoryDependency) error {
				return nil
			})
			if err != nil {
				l.Logger.Error("Error collecting repository dependencies", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
			dependencyEvidences, err := l.EvaluatePolicies(ctx, data, dependencies, dependencyPolicyPaths, l.config.policyData)
			if err != nil {
				l.Logger.Error("Error evaluating dependency policies", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
			if len(dependencyEvidences) > 0 {
				if err := apiHelper.CreateEvidence(ctx, dependencyEvidences); err != nil {
					l.Logger.Error("Error creating dependency evidence", "error", err)
					return &proto.EvalResponse{
						Status: proto.ExecutionStatus_FAILURE,
					}, err
				}
			}
			l.Logger.Debug("Submitted dependency evidence", "repo", repo.GetFullName(), "evidence_count", len(dependencyEvidences))
			l.Logger.Debug("Repository dependency collection complete", "repo", repo.GetFullName(), "dependencies", len(dependencies))
			if len(dependencies) == 0 {
				l.Logger.Warn(
					"Dependency policy paths were provided, but no dependencies are available for evaluation",
					"repo", repo.GetFullName(),
					"dependency_policy_paths", dependencyPolicyPaths,
					"dependency_health_enabled", l.config.dependencyHealthEnabled,
				)
			}
		}
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, nil
}

// FetchRepositories streams repositories selected by the plugin include/exclude configuration.
func (l *GithubReposPlugin) FetchRepositories(ctx context.Context, req *proto.EvalRequest) (chan *github.Repository, chan error) {
	repochan := make(chan *github.Repository)
	errchan := make(chan error)

	var includedRepositories, excludedRepositories []string

	if l.config.IncludedRepositories != "" {
		includedRepositories = strings.Split(l.config.IncludedRepositories, ",")
	}

	if l.config.ExcludedRepositories != "" {
		excludedRepositories = strings.Split(l.config.ExcludedRepositories, ",")
	}

	go func() {
		defer close(repochan)
		defer close(errchan)
		done := false
		paginationOpts := &github.ListOptions{
			PerPage: 100,
			Page:    1,
		}

		for !done {
			repos, resp, err := l.githubClient.Repositories.ListByOrg(ctx, l.config.Organization, &github.RepositoryListByOrgOptions{
				ListOptions: *paginationOpts,
			})
			if err != nil {
				errchan <- err
				return
			}

			for _, repo := range repos {
				if len(includedRepositories) > 0 && !slices.Contains(includedRepositories, repo.GetName()) {
					l.Logger.Trace("Skipping repository (not included)", "repos", repo.GetName())
					continue
				}

				if len(excludedRepositories) > 0 && slices.Contains(excludedRepositories, repo.GetName()) {
					l.Logger.Trace("Skipping repository (excluded):", "repos", repo.GetName())
					continue
				}

				if repo.GetArchived() {
					l.Logger.Trace("Skipping repository (archived):", "repos", repo.GetName())
					continue
				}

				repochan <- repo
			}

			if resp == nil || resp.NextPage == 0 {
				done = true
			} else {
				paginationOpts.Page = resp.NextPage
			}
		}
	}()

	return repochan, errchan
}

// FecthLatestRelease retrieves the latest GitHub release, returning nil when none exists.
func (l *GithubReposPlugin) FecthLatestRelease(ctx context.Context, repo *github.Repository) (*github.RepositoryRelease, error) {
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()

	release, resp, err := l.githubClient.Repositories.GetLatestRelease(ctx, owner, name)
	if err != nil {
		// If there is simply no release, GitHub returns 404. Treat this as "no release" rather than a hard error.
		if resp != nil && resp.Response != nil && resp.StatusCode == 404 {
			l.Logger.Trace("No releases found for repository", "repo", repo.GetFullName())
			return nil, nil
		}
		return nil, err
	}

	return release, nil
}

// GatherConfiguredWorkflows returns workflows configured in the repository.
func (l *GithubReposPlugin) GatherConfiguredWorkflows(ctx context.Context, repo *github.Repository) ([]*github.Workflow, error) {
	workflows, _, err := l.githubClient.Actions.ListWorkflows(ctx, repo.GetOwner().GetLogin(), repo.GetName(), nil)
	if err != nil {
		return nil, err
	}
	return workflows.Workflows, nil
}

// GatherWorkflowRuns returns recent workflow runs for the repository.
func (l *GithubReposPlugin) GatherWorkflowRuns(ctx context.Context, repo *github.Repository) ([]*github.WorkflowRun, error) {
	opts := &github.ListOptions{
		PerPage: 100,
	}
	workflowRuns, _, err := l.githubClient.Actions.ListRepositoryWorkflowRuns(ctx, repo.GetOwner().GetLogin(), repo.GetName(), &github.ListWorkflowRunsOptions{
		ListOptions: *opts,
	})
	if err != nil {
		return nil, err
	}
	return workflowRuns.WorkflowRuns, nil
}

// FetchDeploymentsWithStatuses returns filtered deployment evidence with statuses attached.
func (l *GithubReposPlugin) FetchDeploymentsWithStatuses(ctx context.Context, repo *github.Repository) ([]*DeploymentWithStatuses, error) {
	deployments, err := l.fetchDeploymentsWithStatuses(ctx, repo)
	if err != nil {
		return nil, err
	}
	return l.filterDeployments(deployments), nil
}

// FetchFailedDeploymentsWithStatuses returns deployments whose latest collected statuses include failures.
func (l *GithubReposPlugin) FetchFailedDeploymentsWithStatuses(ctx context.Context, repo *github.Repository) ([]*DeploymentWithStatuses, error) {
	deployments, err := l.fetchDeploymentsWithStatuses(ctx, repo)
	if err != nil {
		return nil, err
	}
	return deploymentsWithFailures(deployments), nil
}

func deploymentsWithFailures(deployments []*DeploymentWithStatuses) []*DeploymentWithStatuses {
	var failed []*DeploymentWithStatuses
	for _, deployment := range deployments {
		if deploymentHasFailed(deployment) {
			failed = append(failed, deployment)
		}
	}

	return failed
}

func (l *GithubReposPlugin) filterDeployments(deployments []*DeploymentWithStatuses) []*DeploymentWithStatuses {
	var filtered []*DeploymentWithStatuses
	for _, deployment := range deployments {
		if deployment == nil || deployment.Deployment == nil {
			continue
		}
		if l.shouldSkipDeployment(deployment.Deployment, deployment.Statuses) {
			continue
		}
		filtered = append(filtered, deployment)
	}
	return filtered
}

func (l *GithubReposPlugin) fetchDeploymentsWithStatuses(ctx context.Context, repo *github.Repository) ([]*DeploymentWithStatuses, error) {
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()

	// Calculate cutoff time based on configured lookback period
	cutoffTime := time.Now().AddDate(0, 0, -l.config.deploymentLookbackDays)

	opts := &github.DeploymentsListOptions{
		ListOptions: github.ListOptions{PerPage: 100, Page: 1},
	}

	var deploymentsWithStatuses []*DeploymentWithStatuses

	for {
		deployments, resp, err := l.githubClient.Repositories.ListDeployments(ctx, owner, name, opts)
		if err != nil {
			if isPermissionError(err) {
				l.Logger.Trace("No permission to fetch deployments", "repo", repo.GetFullName())
				return nil, nil
			}
			return nil, err
		}

		for _, deployment := range deployments {
			// Skip deployments older than the lookback period
			if deployment.CreatedAt != nil && deployment.CreatedAt.Before(cutoffTime) {
				l.Logger.Trace("Skipping old deployment", "deployment_id", deployment.GetID(), "created_at", deployment.CreatedAt.Time, "cutoff", cutoffTime)
				continue
			}

			statuses, _, err := l.githubClient.Repositories.ListDeploymentStatuses(ctx, owner, name, deployment.GetID(), &github.ListOptions{PerPage: 100})
			if err != nil {
				l.Logger.Warn("Error fetching deployment statuses", "deployment_id", deployment.GetID(), "error", err)
				continue
			}

			deploymentsWithStatuses = append(deploymentsWithStatuses, &DeploymentWithStatuses{
				Deployment: deployment,
				Statuses:   statuses,
			})
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	l.Logger.Debug("Fetched deployments", "repo", repo.GetFullName(), "count", len(deploymentsWithStatuses), "lookback_days", l.config.deploymentLookbackDays)
	return deploymentsWithStatuses, nil
}

func deploymentHasFailed(deployment *DeploymentWithStatuses) bool {
	if deployment == nil {
		return false
	}
	for _, status := range deployment.Statuses {
		if status == nil {
			continue
		}
		state := status.GetState()
		if state == "failure" || state == "error" {
			return true
		}
	}
	return false
}

// shouldSkipDeployment determines if a deployment should be filtered out based on configuration
func (l *GithubReposPlugin) shouldSkipDeployment(deployment *github.Deployment, statuses []*github.DeploymentStatus) bool {
	if len(statuses) == 0 {
		// No statuses yet - include it (deployment is pending)
		return false
	}

	// Get the latest status (statuses are returned in reverse chronological order)
	latestStatus := statuses[0]
	latestState := latestStatus.GetState()

	// Filter inactive deployments if OnlyActiveDeployments is enabled
	if l.config.onlyActiveDeployments && latestState == "inactive" {
		l.Logger.Trace("Skipping inactive deployment", "deployment_id", deployment.GetID(), "state", latestState)
		return true
	}

	// Filter failed/error deployments if IncludeFailedDeployments is false (default)
	if !l.config.includeFailedDeployments {
		if latestState == "failure" || latestState == "error" {
			l.Logger.Trace("Skipping failed deployment", "deployment_id", deployment.GetID(), "state", latestState)
			return true
		}
	}

	return false
}

// ListProtectedBranches returns all protected branches visible through the GitHub API.
func (l *GithubReposPlugin) ListProtectedBranches(ctx context.Context, repo *github.Repository) ([]*github.Branch, error) {
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()
	opts := &github.BranchListOptions{
		Protected:   github.Ptr(true),
		ListOptions: github.ListOptions{PerPage: 100, Page: 1},
	}
	var out []*github.Branch
	for {
		branches, resp, err := l.githubClient.Repositories.ListBranches(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, branches...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return out, nil
}

// GetBranchProtectionAndRequiredStatusCheck merges branch protection and ruleset status-check evidence.
func (l *GithubReposPlugin) GetBranchProtectionAndRequiredStatusCheck(ctx context.Context, repo *github.Repository, branch string) (*github.Protection, *github.RequiredStatusChecks, error) {
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()

	// Accumulators for effective required status checks across branch protection and rulesets.
	strict := false
	type checkKey struct {
		context  string
		hasAppID bool
		appID    int64
	}
	checksSet := make(map[checkKey]struct{})

	// 1) Legacy branch protection settings (if present).
	var branchProtection *github.Protection
	protection, _, err := l.githubClient.Repositories.GetBranchProtection(ctx, owner, name, branch)
	if err == nil && protection != nil {
		branchProtection = protection
		if protection.RequiredStatusChecks != nil {
			strict = strict || protection.RequiredStatusChecks.Strict
			// Normalize both Checks and Contexts into Checks entries to avoid dual population.
			if protection.RequiredStatusChecks.Checks != nil {
				for _, c := range *protection.RequiredStatusChecks.Checks {
					if c == nil {
						continue
					}
					key := checkKey{context: c.Context}
					if c.AppID != nil {
						key.hasAppID = true
						key.appID = *c.AppID
					}
					checksSet[key] = struct{}{}
				}
			}
			if protection.RequiredStatusChecks.Contexts != nil {
				for _, ctxName := range *protection.RequiredStatusChecks.Contexts {
					key := checkKey{context: ctxName}
					checksSet[key] = struct{}{}
				}
			}
		}
	} else if err != nil && !errors.Is(err, github.ErrBranchNotProtected) {
		// Non-404s are significant; 404 just means no protection on this branch.
		// We'll log at trace and continue to gather rules-based checks.
		l.Logger.Trace("GetBranchProtection failed", "repo", repo.GetFullName(), "branch", branch, "error", err)
	}

	// 2) Rules that apply to this branch (rulesets API): returns only effective rules.
	rules, _, err := l.githubClient.Repositories.GetRulesForBranch(ctx, owner, name, branch)
	if err != nil {
		// If rules API fails, still return what we have from protection.
		l.Logger.Trace("GetRulesForBranch failed", "repo", repo.GetFullName(), "branch", branch, "error", err)
	} else if rules != nil && rules.RequiredStatusChecks != nil {
		for _, r := range rules.RequiredStatusChecks {
			if r == nil {
				continue
			}
			// Merge strict policy from ruleset parameters (aka up-to-date requirement).
			strict = strict || r.Parameters.StrictRequiredStatusChecksPolicy
			// Merge individual required checks.
			for _, rc := range r.Parameters.RequiredStatusChecks {
				if rc == nil {
					continue
				}
				key := checkKey{context: rc.Context}
				if rc.IntegrationID != nil {
					key.hasAppID = true
					key.appID = *rc.IntegrationID
				}
				checksSet[key] = struct{}{}
			}
		}
	}

	// If no checks found from either source, return nil to indicate absence.
	if len(checksSet) == 0 {
		if !strict {
			return branchProtection, nil, nil
		}
		// If strict is set without explicit checks (edge), still return an empty set with strict.
	}

	// Build a deterministic slice of checks.
	outChecks := make([]*github.RequiredStatusCheck, 0, len(checksSet))
	for key := range checksSet {
		chk := &github.RequiredStatusCheck{Context: key.context}
		if key.hasAppID {
			chk.AppID = github.Ptr(key.appID)
		}
		outChecks = append(outChecks, chk)
	}

	result := &github.RequiredStatusChecks{
		Strict: strict,
	}
	// Always prefer Checks representation to avoid populating both fields.
	result.Checks = &outChecks
	return branchProtection, result, nil
}

// GatherSBOM returns the repository SBOM when GitHub dependency graph access permits it.
func (l *GithubReposPlugin) GatherSBOM(ctx context.Context, repo *github.Repository) (*github.SBOM, error) {
	sbom, resp, err := l.githubClient.DependencyGraph.GetSBOM(ctx, repo.GetOwner().GetLogin(), repo.GetName())
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if err != nil {
		// Permissions errors should be treated as safe here
		// The policy will fail anyways if no sbom exists.
		if isPermissionError(err) {
			return nil, nil
		}
		return nil, err
	}
	return sbom, nil
}

// GatherOpenPullRequests returns open pull requests for the repository.
func (l *GithubReposPlugin) GatherOpenPullRequests(ctx context.Context, repo *github.Repository) ([]*github.PullRequest, error) {
	opts := &github.ListOptions{
		PerPage: 100,
	}
	pullRequests, _, err := l.githubClient.PullRequests.List(ctx, repo.GetOwner().GetLogin(), repo.GetName(), &github.PullRequestListOptions{
		State:       "open",
		ListOptions: *opts,
	})
	if err != nil {
		return nil, err
	}
	return pullRequests, nil
}

// EvaluatePolicies evaluates repository or dependency policy paths and returns generated evidence.
func (l *GithubReposPlugin) EvaluatePolicies(ctx context.Context, data *SaturatedRepository, dependencies []*RepositoryDependency, policyPaths []string, dependencyPolicyData map[string]interface{}) ([]*proto.Evidence, error) {
	if data == nil {
		return nil, errors.New("cannot evaluate policies without repository data")
	}
	if data.PolicyInput == nil {
		data.PolicyInput = data.PolicyData
	}
	if data.Settings == nil {
		if len(policyPaths) == 0 && len(dependencies) == 0 {
			return nil, nil
		}
		return nil, errors.New("cannot evaluate policies without repository settings")
	}

	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	evidences := make([]*proto.Evidence, 0)
	activities = append(activities, &proto.Activity{
		Title: "Collect Github Repository Data",
		Steps: []*proto.Step{
			{
				Title:       "Authenticate with GitHub",
				Description: "Authenticate with the GitHub API via the github-go client.",
			},
			{
				Title:       "Fetch Repository Details",
				Description: "Retrieve detailed information about the GitHub repository.",
			},
		},
	})

	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework"),
				},
			},
			Props: nil,
		},
		{
			Title: "Continuous Compliance Framework - Github Repository Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-github-repositories",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework' Github Repository Plugin"),
				},
			},
			Props: nil,
		},
	}

	components := []*proto.Component{
		{
			Identifier:  "common-components/github-repository",
			Type:        "service",
			Title:       "GitHub Repository",
			Description: "A GitHub repository is a discrete codebase or project workspace hosted within a GitHub Organization or user account. It contains source code, documentation, configuration files, workflows, and version history managed through Git. Repositories support access control, issues, pull requests, branch protection, and automated CI/CD pipelines.",
			Purpose:     "To serve as the authoritative and version-controlled location for a specific software project, enabling secure collaboration, code review, automation, and traceability of changes throughout the development lifecycle.",
		},
		{
			Identifier:  "common-components/version-control",
			Type:        "service",
			Title:       "Version Control",
			Description: "Version control systems track and manage changes to source code and configuration files over time. They provide collaboration, traceability, and the ability to audit or revert code to previous states. Version control enables parallel development workflows and structured release management across software projects.",
			Purpose:     "To maintain a complete and auditable history of code and configuration changes, enable collaboration across distributed teams, and support secure and traceable software development lifecycle (SDLC) practices.",
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("github-repository/%s", data.Settings.GetFullName()),
			Type:       "github-repository",
			Title:      fmt.Sprintf("Github Repository [%s]", data.Settings.GetName()),
			Props: []*proto.Property{
				{
					Name:  "name",
					Value: data.Settings.GetName(),
				},
				{
					Name:  "path",
					Value: data.Settings.GetFullName(),
				},
				{
					Name:  "organization",
					Value: data.Settings.GetOwner().GetName(),
				},
			},
			Links: []*proto.Link{
				{
					Href: data.Settings.GetURL(),
					Text: policyManager.Pointer("Repository URL"),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: "common-components/github-repository",
				},
				{
					Identifier: "common-components/version-control",
				},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("github-repository/%s", data.Settings.GetFullName()),
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("github-organization/%s", data.Settings.GetOwner().GetName()),
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/github-repository",
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/version-control",
		},
	}

	l.Logger.Debug(
		"Evaluating policies",
		"repo", data.Settings.GetFullName(),
		"policy_paths", policyPaths,
		"dependencies", len(dependencies),
	)

	if len(dependencies) == 0 {
		for _, policyPath := range policyPaths {
			l.Logger.Debug("Evaluating repository policy path", "repo", data.Settings.GetFullName(), "policy_path", policyPath)
			l.Logger.Debug(
				"Repository policy data prepared for evaluation",
				"repo", data.Settings.GetFullName(),
				"policy_path", policyPath,
				"policy_data_keys", mapKeys(data.PolicyData),
				"policy_data_count", len(data.PolicyData),
			)
			processor := policyManager.NewPolicyProcessor(
				l.Logger,
				map[string]string{
					"provider":     "github",
					"type":         "repository",
					"repository":   data.Settings.GetName(),
					"organization": data.Settings.GetOwner().GetLogin(),
				},
				subjects,
				components,
				inventory,
				actors,
				activities,
				data.PolicyData,
			)
			evidence, err := processor.GenerateResults(ctx, policyPath, data)
			l.Logger.Debug("Repository policy evaluation complete", "repo", data.Settings.GetFullName(), "policy_path", policyPath, "evidence_count", len(evidence))
			evidences = slices.Concat(evidences, evidence)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
			}
		}
	}

	for _, dependency := range dependencies {
		if dependency == nil {
			continue
		}
		dependencyInput := dependencyPolicyInput(data.Settings, dependency, dependencyPolicyData)
		dependencyComponents := slices.Concat(components, []*proto.Component{dependencyComponent()})
		dependencyInventory := slices.Concat(inventory, []*proto.InventoryItem{dependencyInventoryItem(data.Settings, dependency)})
		dependencySubjects := dependencySubjects(data.Settings, dependency)
		dependencyLabels := map[string]string{
			"provider":     "github",
			"type":         "repository-dependency",
			"repository":   data.Settings.GetName(),
			"organization": data.Settings.GetOwner().GetLogin(),
			"dependency":   dependency.Name,
			"ecosystem":    dependency.Ecosystem,
		}
		if dependency.DeclaredVersion != "" {
			dependencyLabels["dependency_version"] = dependency.DeclaredVersion
		}

		for _, policyPath := range policyPaths {
			l.Logger.Debug(
				"Evaluating dependency policy path",
				"repo", data.Settings.GetFullName(),
				"dependency", dependency.Name,
				"declared_version", dependency.DeclaredVersion,
				"resolved", dependency.Repository != nil && dependency.Repository.Resolved,
				"policy_path", policyPath,
			)
			l.Logger.Debug(
				"Dependency policy data prepared for evaluation",
				"repo", data.Settings.GetFullName(),
				"dependency", dependency.Name,
				"policy_path", policyPath,
				"policy_data_keys", mapKeys(dependencyPolicyData),
				"policy_data_count", len(dependencyPolicyData),
			)
			processor := policyManager.NewPolicyProcessor(
				l.Logger,
				dependencyLabels,
				dependencySubjects,
				dependencyComponents,
				dependencyInventory,
				actors,
				activities,
				dependencyPolicyData,
			)
			evidence, err := processor.GenerateResults(ctx, policyPath, dependencyInput)
			appendDependencyEvidenceLinks(evidence, dependency)
			l.Logger.Debug(
				"Dependency policy evaluation complete",
				"repo", data.Settings.GetFullName(),
				"dependency", dependency.Name,
				"policy_path", policyPath,
				"evidence_count", len(evidence),
			)
			evidences = slices.Concat(evidences, evidence)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
			}
		}
	}

	return evidences, accumulatedErrors
}

func mapKeys(value map[string]interface{}) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

const (
	policyBehaviorRepository = "repository"
	policyBehaviorDependency = "dependency"

	defaultDependencyPolicySource = "plugin-github-repositories-dependency-policies"
)

var defaultPolicyBehaviors = map[string][]string{
	defaultDependencyPolicySource: {policyBehaviorDependency},
}

func requestWithDefaultPolicyBehavior(req *proto.EvalRequest) *proto.EvalRequest {
	if req == nil {
		return nil
	}
	return req.
		WithDefaultPolicyBehavior(defaultPolicyBehaviors).
		WithUndefinedMappedTo([]string{policyBehaviorRepository})
}

func appendDependencyEvidenceLinks(evidences []*proto.Evidence, dependency *RepositoryDependency) {
	if dependency == nil || dependency.Repository == nil || dependency.Repository.URL == "" {
		return
	}
	link := &proto.Link{
		Href: dependency.Repository.URL,
		Rel:  policyManager.Pointer("evidence"),
		Text: policyManager.Pointer("Dependency Repository"),
	}
	for _, evidence := range evidences {
		if evidence == nil || evidenceHasLink(evidence, link.Href) {
			continue
		}
		evidence.Links = append(evidence.Links, link)
	}
}

func evidenceHasLink(evidence *proto.Evidence, href string) bool {
	for _, link := range evidence.GetLinks() {
		if link.GetHref() == href {
			return true
		}
	}
	return false
}

func dependencyPolicyInput(repo *github.Repository, dependency *RepositoryDependency, policyData map[string]interface{}) *DependencyPolicyInput {
	if policyData == nil {
		policyData = map[string]interface{}{}
	}
	return &DependencyPolicyInput{
		Repository: &DependencyParentRepository{
			Organization: repo.GetOwner().GetLogin(),
			Name:         repo.GetName(),
			FullName:     repo.GetFullName(),
			URL:          repo.GetHTMLURL(),
		},
		Dependency: dependency,
		PolicyData: policyData,
	}
}

func dependencyComponent() *proto.Component {
	return &proto.Component{
		Identifier:  "common-components/repository-dependency",
		Type:        "software",
		Title:       "Repository Dependency",
		Description: "A software dependency declared by a monitored source repository.",
		Purpose:     "To represent third-party or internally maintained software components that the repository relies on.",
	}
}

func dependencyInventoryItem(repo *github.Repository, dependency *RepositoryDependency) *proto.InventoryItem {
	props := []*proto.Property{
		{Name: "name", Value: dependency.Name},
		{Name: "ecosystem", Value: dependency.Ecosystem},
		{Name: "repository", Value: repo.GetFullName()},
	}
	if dependency.DeclaredVersion != "" {
		props = append(props, &proto.Property{Name: "declared_version", Value: dependency.DeclaredVersion})
	}

	links := []*proto.Link{}
	if dependency.Repository != nil && dependency.Repository.URL != "" {
		links = append(links, &proto.Link{
			Href: dependency.Repository.URL,
			Text: policyManager.Pointer("Dependency Repository URL"),
		})
	}

	return &proto.InventoryItem{
		Identifier: dependencyIdentifier(repo, dependency),
		Type:       "repository-dependency",
		Title:      fmt.Sprintf("Repository Dependency [%s]", dependency.Name),
		Props:      props,
		Links:      links,
		ImplementedComponents: []*proto.InventoryItemImplementedComponent{
			{Identifier: "common-components/repository-dependency"},
		},
	}
}

func dependencySubjects(repo *github.Repository, dependency *RepositoryDependency) []*proto.Subject {
	return []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: dependencyIdentifier(repo, dependency),
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("github-repository/%s", repo.GetFullName()),
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/repository-dependency",
		},
	}
}

func dependencyIdentifier(repo *github.Repository, dependency *RepositoryDependency) string {
	if dependency.DeclaredVersion == "" {
		return fmt.Sprintf("github-repository-dependency/%s/%s", repo.GetFullName(), dependency.Name)
	}
	return fmt.Sprintf("github-repository-dependency/%s/%s@%s", repo.GetFullName(), dependency.Name, dependency.DeclaredVersion)
}

// isPermissionError returns true if the error from the GitHub client indicates
// a permissions or visibility issue (e.g., 401/403/404).
func isPermissionError(err error) bool {
	return isHTTPStatusError(err, 401, 403, 404)
}

func isHTTPStatusError(err error, statusCodes ...int) bool {
	if err == nil {
		return false
	}
	var ger *github.ErrorResponse
	if errors.As(err, &ger) {
		if ger.Response != nil {
			for _, statusCode := range statusCodes {
				if ger.Response.StatusCode == statusCode {
					return true
				}
			}
		}
	}
	return false
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	ghRepos := &GithubReposPlugin{
		Logger: logger,
	}

	logger.Info("Starting GitHub Repositories Plugin")
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerV2GRPCPlugin{
				Impl: ghRepos,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
