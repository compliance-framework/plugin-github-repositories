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
