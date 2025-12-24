package main

import (
	"context"

	"github.com/google/go-github/v71/github"
)

var defaultCodeOwnerPaths = []string{
	"CODEOWNERS",
	".github/CODEOWNERS",
	"docs/CODEOWNERS",
}

// FetchCodeOwners attempts to retrieve the CODEOWNERS file for the repository.
// If the file cannot be found or is inaccessible due to permissions, the function
// returns nil and logs the reason so policy evaluation can proceed with an empty value.
func (l *GithubReposPlugin) FetchCodeOwners(ctx context.Context, repo *github.Repository) (*github.RepositoryContent, error) {
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()

	for _, path := range defaultCodeOwnerPaths {
		file, _, resp, err := l.githubClient.Repositories.GetContents(ctx, owner, name, path, nil)
		if err != nil {
			if resp != nil && resp.StatusCode == 404 {
				continue
			}
			if isPermissionError(err) {
				l.Logger.Debug("CODEOWNERS fetch skipped due to permissions", "repo", repo.GetFullName(), "path", path, "error", err)
				return nil, nil
			}
			return nil, err
		}
		if file != nil {
			l.Logger.Debug("Found CODEOWNERS file", "repo", repo.GetFullName(), "path", path)
			return file, nil
		}
	}

	l.Logger.Debug("No CODEOWNERS file found for repository", "repo", repo.GetFullName())
	return nil, nil
}
