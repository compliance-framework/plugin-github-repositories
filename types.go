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
	RequiredSignatures           bool     `json:"required_signatures"`
	RequiredDeployments          []string `json:"required_deployments,omitempty"`
	CodeScanningTools            []string `json:"code_scanning_tools,omitempty"`
	RequiredApprovingReviewCount int      `json:"required_approving_review_count,omitempty"`
	DismissStaleReviewsOnPush    bool     `json:"dismiss_stale_reviews_on_push,omitempty"`
	RequireCodeOwnerReview       bool     `json:"require_code_owner_review,omitempty"`
}

type RepositoryDependency struct {
	Name             string                      `json:"name"`
	Ecosystem        string                      `json:"ecosystem"`
	SourceFile       string                      `json:"source_file"`
	Direct           bool                        `json:"direct"`
	DeclaredVersion  string                      `json:"declared_version"`
	Repository       *DependencyRepository       `json:"repository"`
	Health           *DependencyHealth           `json:"health"`
	SupplyChain      *DependencySupplyChain      `json:"supply_chain"`
	CollectionStatus *DependencyCollectionStatus `json:"collection_status"`
}

type DependencyPolicyInput struct {
	Repository *DependencyParentRepository `json:"repository"`
	Dependency *RepositoryDependency       `json:"dependency"`
	PolicyData map[string]interface{}      `json:"policy_data"`
}

type DependencyParentRepository struct {
	Organization string `json:"organization"`
	Name         string `json:"name"`
	FullName     string `json:"full_name"`
	URL          string `json:"url,omitempty"`
}

type DependencyRepository struct {
	Provider string `json:"provider,omitempty"`
	Owner    string `json:"owner,omitempty"`
	Name     string `json:"name,omitempty"`
	URL      string `json:"url,omitempty"`
	Resolved bool   `json:"resolved"`
}

type DependencyHealth struct {
	RepositoryArchived bool                        `json:"repository_archived"`
	LatestRelease      *DependencyRelease          `json:"latest_release,omitempty"`
	LatestCommit       *DependencyCommit           `json:"latest_commit,omitempty"`
	Workflows          *DependencyWorkflowSummary  `json:"workflows,omitempty"`
	PullRequests       *DependencyPullRequestStats `json:"pull_requests,omitempty"`
}

type DependencyRelease struct {
	Tag         string     `json:"tag,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
}

type DependencyCommit struct {
	SHA         string     `json:"sha,omitempty"`
	CommittedAt *time.Time `json:"committed_at,omitempty"`
}

type DependencyWorkflowSummary struct {
	Count                  int                    `json:"count"`
	LatestDefaultBranchRun *DependencyWorkflowRun `json:"latest_default_branch_run,omitempty"`
}

type DependencyWorkflowRun struct {
	Status     string     `json:"status,omitempty"`
	Conclusion string     `json:"conclusion,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
}

type DependencyPullRequestStats struct {
	OpenCount                           int        `json:"open_count"`
	OpenCountCapped                     bool       `json:"open_count_capped"`
	OldestOpenCreatedAt                 *time.Time `json:"oldest_open_created_at,omitempty"`
	RecentClosedCount                   int        `json:"recent_closed_count"`
	RecentClosedCountCapped             bool       `json:"recent_closed_count_capped"`
	MedianDaysToClose                   *float64   `json:"median_days_to_close,omitempty"`
	MedianHoursToFirstInteraction       *float64   `json:"median_hours_to_first_interaction,omitempty"`
	FirstInteractionSampledPullRequests int        `json:"first_interaction_sampled_pull_requests"`
}

type DependencySupplyChain struct {
	License *DependencyLicenseSummary `json:"license,omitempty"`
	SBOM    *DependencySBOMSummary    `json:"sbom,omitempty"`
}

type DependencyLicenseSummary struct {
	SPDXID    string `json:"spdx_id,omitempty"`
	Name      string `json:"name,omitempty"`
	URL       string `json:"url,omitempty"`
	Collected bool   `json:"collected"`
}

type DependencySBOMSummary struct {
	Available           bool       `json:"available"`
	PackageCount        int        `json:"package_count"`
	SPDXID              string     `json:"spdx_id,omitempty"`
	SPDXVersion         string     `json:"spdx_version,omitempty"`
	CreationInfoCreated *time.Time `json:"creation_info_created,omitempty"`
	Collected           bool       `json:"collected"`
}

type DependencyCollectionStatus struct {
	DependencyParsed   bool                         `json:"dependency_parsed"`
	RepositoryResolved bool                         `json:"repository_resolved"`
	HealthCollected    bool                         `json:"health_collected"`
	LicenseCollected   bool                         `json:"license_collected"`
	SBOMCollected      bool                         `json:"sbom_collected"`
	Errors             []*DependencyCollectionError `json:"errors"`
}

type DependencyCollectionError struct {
	Scope   string `json:"scope"`
	Message string `json:"message"`
}
