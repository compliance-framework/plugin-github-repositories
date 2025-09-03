package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

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
