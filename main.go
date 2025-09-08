package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/mitchellh/mapstructure"
)

type Validator interface {
	Validate() error
}

type PluginConfig struct {
	Token                string `mapstructure:"token"`
	Organization         string `mapstructure:"organization"`
	IncludedRepositories string `mapstructure:"included_repositories"`
	ExcludedRepositories string `mapstructure:"excluded_repositories"`
}

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

type SaturatedRepository struct {
	Settings     *github.Repository    `json:"settings"`
	Workflows    []*github.Workflow    `json:"workflows"`
	WorkflowRuns []*github.WorkflowRun `json:"workflow_runs"`
	// ProtectedBranches is the list of protected branches in the repository
	ProtectedBranches []string `json:"protected_branches"`
	// RequiredStatusChecks maps branch name -> required status checks configuration
	RequiredStatusChecks map[string]*github.RequiredStatusChecks `json:"required_status_checks"`
	SBOM                 *github.SBOM                            `json:"sbom"`
}

type GithubReposPlugin struct {
	Logger hclog.Logger

	config       *PluginConfig
	githubClient *github.Client
}

func (l *GithubReposPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.Logger.Info("Configuring GitHub Repositories Plugin")
	config := &PluginConfig{}

	if err := mapstructure.Decode(req.Config, config); err != nil {
		l.Logger.Error("Error decoding config", "error", err)
		return nil, err
	}

	if err := config.Validate(); err != nil {
		l.Logger.Error("Error validating config", "error", err)
		return nil, err
	}

	l.config = config
	l.githubClient = github.NewClient(nil).WithAuthToken(config.Token)

	return &proto.ConfigureResponse{}, nil
}

func (l *GithubReposPlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	repochan, errchan := l.FetchRepositories(ctx, req)
	done := false

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
			l.Logger.Debug("Processing repository:", "repo_name", repo.GetName())

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
			requiredChecks := make(map[string]*github.RequiredStatusChecks)
			for _, b := range branches {
				if b == nil || b.Name == nil {
					continue
				}
				name := b.GetName()
				l.Logger.Debug("Found protected branch", "branch", name)
				branchNames = append(branchNames, name)
				checks, err := l.GetRequiredStatusChecks(ctx, repo, name)
				l.Logger.Debug("Fetched required status checks", "branch", name, "checks", checks)
				if err != nil {
					l.Logger.Trace("Branch required checks fetch failed", "repo", repo.GetFullName(), "branch", name, "error", err)
					continue
				}
				if checks != nil {
					requiredChecks[name] = checks
				}
			}
			// Fallback to default branch if none collected
			if len(requiredChecks) == 0 {
				l.Logger.Debug("No protected branches with required status checks found, checking default branch", "repo", repo.GetFullName())
				if def := repo.GetDefaultBranch(); def != "" {
					if checks, err := l.GetRequiredStatusChecks(ctx, repo, def); err == nil && checks != nil {
						requiredChecks[def] = checks
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

			data := &SaturatedRepository{
				Settings:             repo,
				Workflows:            workflows,
				WorkflowRuns:         workflowRuns,
				ProtectedBranches:    branchNames,
				RequiredStatusChecks: requiredChecks,
				SBOM:                 sbom,
			}

			// Uncomment to check the data that is being passed through from
			// the client, as data formats are often slightly different than
			// the raw API endpoints
			jsonData, _ := json.MarshalIndent(data, "", "  ")
			_ = os.WriteFile(fmt.Sprintf("./dist/%s.json", repo.GetName()), jsonData, 0644)

			evidences, err := l.EvaluatePolicies(ctx, data, req)
			if err != nil {
				l.Logger.Error("Error evaluating policies", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			if err := apiHelper.CreateEvidence(ctx, evidences); err != nil {
				l.Logger.Error("Error creating evidence", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			l.Logger.Debug("Successfully processed repository:", "repo_name", repo.GetName())
		}
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, nil
}

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
				done = true
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

			if resp.NextPage == 0 {
				done = true
			} else {
				paginationOpts.Page = resp.NextPage
			}
		}
	}()

	return repochan, errchan
}

func (l *GithubReposPlugin) GatherConfiguredWorkflows(ctx context.Context, repo *github.Repository) ([]*github.Workflow, error) {
	workflows, _, err := l.githubClient.Actions.ListWorkflows(ctx, repo.GetOwner().GetLogin(), repo.GetName(), nil)
	if err != nil {
		return nil, err
	}
	return workflows.Workflows, nil
}

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
		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}
	return out, nil
}

func (l *GithubReposPlugin) GetRequiredStatusChecks(ctx context.Context, repo *github.Repository, branch string) (*github.RequiredStatusChecks, error) {
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
	protection, _, err := l.githubClient.Repositories.GetBranchProtection(ctx, owner, name, branch)
	if err == nil && protection != nil && protection.RequiredStatusChecks != nil {
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
	} else if err != nil {
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
			return nil, nil
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
	return result, nil
}

func (l *GithubReposPlugin) GatherSBOM(ctx context.Context, repo *github.Repository) (*github.SBOM, error) {
	sbom, _, err := l.githubClient.DependencyGraph.GetSBOM(ctx, repo.GetOwner().GetLogin(), repo.GetName())
	if err != nil {
		return nil, err
	}
	return sbom, nil
}

func (l *GithubReposPlugin) EvaluatePolicies(ctx context.Context, data *SaturatedRepository, req *proto.EvalRequest) ([]*proto.Evidence, error) {
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

	for _, policyPath := range req.GetPolicyPaths() {
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
		)
		evidence, err := processor.GenerateResults(ctx, policyPath, data)
		evidences = slices.Concat(evidences, evidence)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}
	}

	return evidences, accumulatedErrors
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
			"runner": &runner.RunnerGRPCPlugin{
				Impl: ghRepos,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})

}
