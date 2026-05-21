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

// RepositoryCollaborator captures a direct repository collaborator and their permissions.
type RepositoryCollaborator struct {
	Login       string          `json:"login"`
	RoleName    string          `json:"role_name"`
	Permissions map[string]bool `json:"permissions"`
}

// RepositoryTeam captures a GitHub team with repository access and known members.
type RepositoryTeam struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Slug        string          `json:"slug"`
	Permission  string          `json:"permission"`
	Permissions map[string]bool `json:"permissions"`
	Members     []string        `json:"members"`
}

// EnvironmentReviewer represents a user or team configured as an environment reviewer.
type EnvironmentReviewer struct {
	Type  string `json:"type"`
	ID    int64  `json:"id,omitempty"`
	Login string `json:"login,omitempty"`
	Slug  string `json:"slug,omitempty"`
	Name  string `json:"name,omitempty"`
}

// EnvironmentProtectionRule captures a GitHub environment protection rule.
type EnvironmentProtectionRule struct {
	ID                int64                  `json:"id"`
	Type              string                 `json:"type"`
	WaitTimer         int                    `json:"wait_timer,omitempty"`
	PreventSelfReview bool                   `json:"prevent_self_review"`
	Reviewers         []*EnvironmentReviewer `json:"reviewers,omitempty"`
}

// EnvironmentBranchPolicy captures branch deployment restrictions for an environment.
type EnvironmentBranchPolicy struct {
	ProtectedBranches    bool `json:"protected_branches"`
	CustomBranchPolicies bool `json:"custom_branch_policies"`
}

// RepositoryEnvironment captures GitHub environment settings relevant to deployment policy checks.
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

// BranchRuleEvidence captures effective branch rules for repository policy evaluation.
type BranchRuleEvidence struct {
	RequiredSignatures           bool     `json:"required_signatures"`
	RequiredDeployments          []string `json:"required_deployments,omitempty"`
	CodeScanningTools            []string `json:"code_scanning_tools,omitempty"`
	RequiredApprovingReviewCount int      `json:"required_approving_review_count,omitempty"`
	DismissStaleReviewsOnPush    bool     `json:"dismiss_stale_reviews_on_push,omitempty"`
	RequireCodeOwnerReview       bool     `json:"require_code_owner_review,omitempty"`
}

// RepositoryDependency captures a direct dependency and any collected upstream health facts.
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

// DependencyPolicyInput is the policy input shape for dependency-granular evaluation.
type DependencyPolicyInput struct {
	Repository *DependencyParentRepository `json:"repository"`
	Dependency *RepositoryDependency       `json:"dependency"`
	PolicyData map[string]interface{}      `json:"policy_data"`
}

// DependencyParentRepository identifies the repository that declared a dependency.
type DependencyParentRepository struct {
	Organization string `json:"organization"`
	Name         string `json:"name"`
	FullName     string `json:"full_name"`
	URL          string `json:"url,omitempty"`
}

// DependencyRepository identifies the upstream repository resolved for a dependency.
type DependencyRepository struct {
	Provider string `json:"provider,omitempty"`
	Owner    string `json:"owner,omitempty"`
	Name     string `json:"name,omitempty"`
	URL      string `json:"url,omitempty"`
	Resolved bool   `json:"resolved"`
}

// DependencyHealth captures maintenance and activity signals for a resolved dependency repository.
type DependencyHealth struct {
	RepositoryArchived bool                        `json:"repository_archived"`
	LatestRelease      *DependencyRelease          `json:"latest_release,omitempty"`
	LatestCommit       *DependencyCommit           `json:"latest_commit,omitempty"`
	Workflows          *DependencyWorkflowSummary  `json:"workflows,omitempty"`
	PullRequests       *DependencyPullRequestStats `json:"pull_requests,omitempty"`
}

// DependencyRelease captures the latest release observed for a dependency.
type DependencyRelease struct {
	Tag         string     `json:"tag,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
}

// DependencyCommit captures the latest default-branch commit observed for a dependency.
type DependencyCommit struct {
	SHA         string     `json:"sha,omitempty"`
	CommittedAt *time.Time `json:"committed_at,omitempty"`
}

// DependencyWorkflowSummary summarizes workflow availability for a dependency repository.
type DependencyWorkflowSummary struct {
	Count                  int                    `json:"count"`
	LatestDefaultBranchRun *DependencyWorkflowRun `json:"latest_default_branch_run,omitempty"`
}

// DependencyWorkflowRun captures the latest default-branch workflow run state.
type DependencyWorkflowRun struct {
	Status     string     `json:"status,omitempty"`
	Conclusion string     `json:"conclusion,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
}

// DependencyPullRequestStats summarizes dependency repository pull request activity.
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

// DependencySupplyChain captures dependency license and SBOM evidence.
type DependencySupplyChain struct {
	License *DependencyLicenseSummary `json:"license,omitempty"`
	SBOM    *DependencySBOMSummary    `json:"sbom,omitempty"`
}

// DependencyLicenseSummary captures collected dependency license metadata.
type DependencyLicenseSummary struct {
	SPDXID    string `json:"spdx_id,omitempty"`
	Name      string `json:"name,omitempty"`
	URL       string `json:"url,omitempty"`
	Collected bool   `json:"collected"`
}

// DependencySBOMSummary captures collected dependency SBOM metadata.
type DependencySBOMSummary struct {
	Available           bool       `json:"available"`
	PackageCount        int        `json:"package_count"`
	SPDXID              string     `json:"spdx_id,omitempty"`
	SPDXVersion         string     `json:"spdx_version,omitempty"`
	CreationInfoCreated *time.Time `json:"creation_info_created,omitempty"`
	Collected           bool       `json:"collected"`
}

// DependencyCollectionStatus records which dependency collection stages completed.
type DependencyCollectionStatus struct {
	DependencyParsed   bool                         `json:"dependency_parsed"`
	RepositoryResolved bool                         `json:"repository_resolved"`
	HealthCollected    bool                         `json:"health_collected"`
	LicenseCollected   bool                         `json:"license_collected"`
	SBOMCollected      bool                         `json:"sbom_collected"`
	Errors             []*DependencyCollectionError `json:"errors"`
}

// DependencyCollectionError records a non-fatal dependency collection failure.
type DependencyCollectionError struct {
	Scope   string `json:"scope"`
	Message string `json:"message"`
}
