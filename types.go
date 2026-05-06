package main

import (
	"time"

	"github.com/google/go-github/v71/github"
)

// OpenPullRequest represents a pull request alongside its reviews.
// Reviews are nested so policy evaluation can reason over reviewers
// and their specific discussion threads without performing joins in Rego.
type OpenPullRequest struct {
	*github.PullRequest
	Reviews []*PullRequestReview `json:"reviews"`
}

// PullRequestReview captures a single review paired with its discussion threads.
type PullRequestReview struct {
	*github.PullRequestReview
	Threads []*PullRequestReviewThread `json:"threads"`
}

// PullRequestReviewThread captures the GraphQL thread metadata plus its comments.
type PullRequestReviewThread struct {
	ID         string                            `json:"id"`
	IsResolved bool                              `json:"is_resolved"`
	Comments   []*PullRequestReviewThreadComment `json:"comments"`
}

// PullRequestReviewThreadComment is a thin struct used by policies to reason about inline discussion.
type PullRequestReviewThreadComment struct {
	ID               string     `json:"id"`
	Body             string     `json:"body"`
	URL              string     `json:"url"`
	ReviewID         string     `json:"review_id,omitempty"`
	DiffHunk         string     `json:"diff_hunk"`
	Path             string     `json:"path"`
	Position         *int       `json:"position,omitempty"`
	OriginalPosition *int       `json:"original_position,omitempty"`
	ReplyToID        string     `json:"reply_to_id,omitempty"`
	CreatedAt        *time.Time `json:"created_at,omitempty"`
	UpdatedAt        *time.Time `json:"updated_at,omitempty"`
}

// OrgTeam captures a GitHub team and its member logins for CODEOWNERS evaluation.
type OrgTeam struct {
	ID      int64    `json:"id"`
	Name    string   `json:"name"`
	Slug    string   `json:"slug"`
	Members []string `json:"members"`
}

type RepositoryCollaborator struct {
	Login       string          `json:"login"`
	RoleName    string          `json:"role_name"`
	Permissions map[string]bool `json:"permissions"`
}

type RepositoryTeam struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Slug        string          `json:"slug"`
	Permission  string          `json:"permission"`
	Permissions map[string]bool `json:"permissions"`
	Members     []string        `json:"members"`
}

type EnvironmentReviewer struct {
	Type  string `json:"type"`
	ID    int64  `json:"id,omitempty"`
	Login string `json:"login,omitempty"`
	Slug  string `json:"slug,omitempty"`
	Name  string `json:"name,omitempty"`
}

type EnvironmentProtectionRule struct {
	ID                int64                  `json:"id"`
	Type              string                 `json:"type"`
	WaitTimer         int                    `json:"wait_timer,omitempty"`
	PreventSelfReview bool                   `json:"prevent_self_review"`
	Reviewers         []*EnvironmentReviewer `json:"reviewers,omitempty"`
}

type EnvironmentBranchPolicy struct {
	ProtectedBranches    bool `json:"protected_branches"`
	CustomBranchPolicies bool `json:"custom_branch_policies"`
}

type RepositoryEnvironment struct {
	ID                     int64                        `json:"id"`
	Name                   string                       `json:"name"`
	URL                    string                       `json:"url,omitempty"`
	HTMLURL                string                       `json:"html_url,omitempty"`
	WaitTimer              int                          `json:"wait_timer,omitempty"`
	CanAdminsBypass        bool                         `json:"can_admins_bypass"`
	Reviewers              []*EnvironmentReviewer       `json:"reviewers,omitempty"`
	ProtectionRules        []*EnvironmentProtectionRule `json:"protection_rules,omitempty"`
	DeploymentBranchPolicy *EnvironmentBranchPolicy     `json:"deployment_branch_policy,omitempty"`
}

type BranchRuleEvidence struct {
	RequiredSignatures  bool     `json:"required_signatures"`
	RequiredDeployments []string `json:"required_deployments,omitempty"`
	CodeScanningTools   []string `json:"code_scanning_tools,omitempty"`
}
