package main

import (
	"context"
	"errors"
	"fmt"
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
	Settings *github.Repository `json:"settings"`
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

			data := &SaturatedRepository{
				Settings: repo,
			}

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

func (l *GithubReposPlugin) EvaluatePolicies(ctx context.Context, data *SaturatedRepository, req *proto.EvalRequest) ([]*proto.Evidence, error) {
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	evidences := make([]*proto.Evidence, 0)
	activities = append(activities, &proto.Activity{
		Title: "Collect Github Repository Data",
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

	return evidences, nil
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
