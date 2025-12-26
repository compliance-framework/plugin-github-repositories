package main

import (
	"context"
	"fmt"

	"github.com/google/go-github/v71/github"
	"github.com/shurcooL/githubv4"
)

const (
	reviewThreadPageSize  = 50
	threadCommentPageSize = 50
)

// FetchPullRequestReviews returns a map keyed by pull request ID containing all reviews for each PR.
func (l *GithubReposPlugin) FetchPullRequestReviews(ctx context.Context, repo *github.Repository, prs []*github.PullRequest) (map[int64][]*github.PullRequestReview, error) {
	reviewsByPR := make(map[int64][]*github.PullRequestReview, len(prs))
	if repo == nil {
		return reviewsByPR, nil
	}

	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()

	for _, pr := range prs {
		if pr == nil {
			continue
		}

		prKey := pullRequestKey(pr)
		opts := &github.ListOptions{PerPage: 100, Page: 1}
		var reviews []*github.PullRequestReview

		for {
			batch, resp, err := l.githubClient.PullRequests.ListReviews(ctx, owner, name, pr.GetNumber(), opts)
			if err != nil {
				return nil, err
			}
			reviews = append(reviews, batch...)
			if resp == nil || resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}

		reviewsByPR[prKey] = reviews
	}

	return reviewsByPR, nil
}

// ProcessOpenPullRequests nests reviews and their threads beneath each pull request.
func ProcessOpenPullRequests(prs []*github.PullRequest, reviews map[int64][]*github.PullRequestReview, reviewThreads map[int64][]*PullRequestReviewThread) []*OpenPullRequest {
	openPRs := make([]*OpenPullRequest, 0, len(prs))

	for _, pr := range prs {
		if pr == nil {
			continue
		}

		prKey := pullRequestKey(pr)
		reviewList := reviews[prKey]

		openReviews := make([]*PullRequestReview, 0, len(reviewList))
		for _, review := range reviewList {
			if review == nil {
				continue
			}
			reviewID := review.GetID()
			openReviews = append(openReviews, &PullRequestReview{
				PullRequestReview: review,
				Threads:           reviewThreads[reviewID],
			})
		}

		openPRs = append(openPRs, &OpenPullRequest{
			PullRequest: pr,
			Reviews:     openReviews,
		})
	}

	return openPRs
}

// GatherReviewsAndComments orchestrates fetching reviews and comments before producing the enriched slice.
func (l *GithubReposPlugin) GatherReviewsAndComments(ctx context.Context, repo *github.Repository, prs []*github.PullRequest) ([]*OpenPullRequest, error) {
	if len(prs) == 0 {
		return nil, nil
	}

	reviewsByPR, err := l.FetchPullRequestReviews(ctx, repo, prs)
	if err != nil {
		l.Logger.Error("failed to fetch pull request reviews", "error", err)
		return ProcessOpenPullRequests(prs, nil, nil), nil
	}

	threadsByReview, err := l.FetchReviewThreads(ctx, prs, reviewsByPR)
	if err != nil {
		l.Logger.Error("failed to fetch pull request review threads", "error", err)
		return ProcessOpenPullRequests(prs, reviewsByPR, nil), nil
	}

	return ProcessOpenPullRequests(prs, reviewsByPR, threadsByReview), nil
}

func pullRequestKey(pr *github.PullRequest) int64 {
	if pr == nil {
		return 0
	}
	if id := pr.GetID(); id != 0 {
		return id
	}
	return int64(pr.GetNumber())
}

func (l *GithubReposPlugin) FetchReviewThreads(ctx context.Context, prs []*github.PullRequest, reviewsByPR map[int64][]*github.PullRequestReview) (map[int64][]*PullRequestReviewThread, error) {
	threadsByReview := make(map[int64][]*PullRequestReviewThread)
	if l.graphqlClient == nil {
		return threadsByReview, nil
	}

	for _, pr := range prs {
		if pr == nil {
			continue
		}
		prNodeID := pr.GetNodeID()
		if prNodeID == "" {
			continue
		}

		prKey := pullRequestKey(pr)
		reviewList := reviewsByPR[prKey]
		if len(reviewList) == 0 {
			continue
		}

		reviewNodeToID := make(map[string]int64, len(reviewList))
		for _, review := range reviewList {
			if review == nil {
				continue
			}
			nodeID := review.GetNodeID()
			if nodeID == "" {
				continue
			}
			reviewNodeToID[nodeID] = review.GetID()
		}
		if len(reviewNodeToID) == 0 {
			continue
		}

		threadList, err := l.fetchThreadsForPullRequest(ctx, prNodeID)
		if err != nil {
			return nil, err
		}
		if len(threadList) == 0 {
			continue
		}

		for _, thread := range threadList {
			if thread == nil {
				continue
			}
			reviewsForThread := make(map[int64]struct{})
			for _, comment := range thread.Comments {
				if comment == nil || comment.ReviewID == "" {
					continue
				}
				if reviewID, ok := reviewNodeToID[comment.ReviewID]; ok {
					reviewsForThread[reviewID] = struct{}{}
				}
			}
			if len(reviewsForThread) == 0 {
				continue
			}
			for reviewID := range reviewsForThread {
				threadsByReview[reviewID] = append(threadsByReview[reviewID], thread)
			}
		}
	}

	return threadsByReview, nil
}

func (l *GithubReposPlugin) fetchThreadsForPullRequest(ctx context.Context, prNodeID string) ([]*PullRequestReviewThread, error) {
	var threads []*PullRequestReviewThread
	var threadCursor *githubv4.String

	for {
		var query struct {
			Node struct {
				PullRequest struct {
					ReviewThreads struct {
						Nodes    []reviewThreadNode
						PageInfo struct {
							HasNextPage githubv4.Boolean
							EndCursor   githubv4.String
						}
					} `graphql:"reviewThreads(first: $threadsFirst, after: $threadsCursor)"`
				} `graphql:"... on PullRequest"`
			} `graphql:"node(id: $pullRequestID)"`
		}

		variables := map[string]interface{}{
			"pullRequestID": githubv4.ID(prNodeID),
			"threadsFirst":  githubv4.Int(reviewThreadPageSize),
			"threadsCursor": threadCursor,
			"commentsFirst": githubv4.Int(threadCommentPageSize),
		}

		if err := l.graphqlClient.Query(ctx, &query, variables); err != nil {
			return nil, err
		}

		threadConnection := query.Node.PullRequest.ReviewThreads
		for _, node := range threadConnection.Nodes {
			threadNode := node
			if bool(node.Comments.PageInfo.HasNextPage) {
				additional, err := l.fetchAdditionalThreadComments(ctx, node.ID, node.Comments.PageInfo.EndCursor)
				if err != nil {
					return nil, err
				}
				threadNode.Comments.Nodes = append(threadNode.Comments.Nodes, additional...)
			}
			threads = append(threads, convertGraphQLThread(threadNode))
		}

		if !bool(threadConnection.PageInfo.HasNextPage) {
			break
		}
		next := threadConnection.PageInfo.EndCursor
		threadCursor = new(githubv4.String)
		*threadCursor = next
	}

	return threads, nil
}

func (l *GithubReposPlugin) fetchAdditionalThreadComments(ctx context.Context, threadID githubv4.ID, startCursor githubv4.String) ([]reviewThreadCommentNode, error) {
	var allComments []reviewThreadCommentNode
	cursor := new(githubv4.String)
	*cursor = startCursor

	for {
		var query struct {
			Node struct {
				PullRequestReviewThread struct {
					Comments struct {
						Nodes    []reviewThreadCommentNode
						PageInfo struct {
							HasNextPage githubv4.Boolean
							EndCursor   githubv4.String
						}
					} `graphql:"comments(first: $commentsFirst, after: $commentsCursor)"`
				} `graphql:"... on PullRequestReviewThread"`
			} `graphql:"node(id: $threadID)"`
		}

		variables := map[string]interface{}{
			"threadID":       threadID,
			"commentsFirst":  githubv4.Int(threadCommentPageSize),
			"commentsCursor": cursor,
		}

		if err := l.graphqlClient.Query(ctx, &query, variables); err != nil {
			return nil, err
		}

		commentConnection := query.Node.PullRequestReviewThread.Comments
		allComments = append(allComments, commentConnection.Nodes...)

		if !bool(commentConnection.PageInfo.HasNextPage) {
			break
		}
		next := commentConnection.PageInfo.EndCursor
		cursor = new(githubv4.String)
		*cursor = next
	}

	return allComments, nil
}

type reviewThreadNode struct {
	ID         githubv4.ID
	IsResolved githubv4.Boolean
	Comments   struct {
		Nodes    []reviewThreadCommentNode
		PageInfo struct {
			HasNextPage githubv4.Boolean
			EndCursor   githubv4.String
		}
	} `graphql:"comments(first: $commentsFirst)"`
}

type reviewThreadCommentNode struct {
	ID               githubv4.ID
	Body             githubv4.String
	URL              githubv4.URI
	Author           struct{ Login githubv4.String } `graphql:"author"`
	DiffHunk         githubv4.String
	Path             githubv4.String
	Position         *githubv4.Int
	OriginalPosition *githubv4.Int
	ReplyTo          *struct {
		ID githubv4.ID
	} `graphql:"replyTo"`
	PullRequestReview *struct {
		ID githubv4.ID
	} `graphql:"pullRequestReview"`
	CreatedAt githubv4.DateTime
	UpdatedAt githubv4.DateTime
}

func convertGraphQLThread(node reviewThreadNode) *PullRequestReviewThread {
	thread := &PullRequestReviewThread{
		ID:         idToString(node.ID),
		IsResolved: bool(node.IsResolved),
		Comments:   make([]*PullRequestReviewThreadComment, 0, len(node.Comments.Nodes)),
	}
	for _, commentNode := range node.Comments.Nodes {
		thread.Comments = append(thread.Comments, convertGraphQLThreadComment(commentNode))
	}
	return thread
}

func convertGraphQLThreadComment(node reviewThreadCommentNode) *PullRequestReviewThreadComment {
	comment := &PullRequestReviewThreadComment{
		ID:       idToString(node.ID),
		Body:     string(node.Body),
		URL:      node.URL.String(),
		DiffHunk: string(node.DiffHunk),
		Path:     string(node.Path),
	}

	if node.Position != nil {
		pos := int(*node.Position)
		comment.Position = &pos
	}
	if node.OriginalPosition != nil {
		pos := int(*node.OriginalPosition)
		comment.OriginalPosition = &pos
	}
	if node.ReplyTo != nil {
		if replyTo := idToString(node.ReplyTo.ID); replyTo != "" {
			comment.ReplyToID = replyTo
		}
	}
	if node.PullRequestReview != nil {
		comment.ReviewID = idToString(node.PullRequestReview.ID)
	}
	created := node.CreatedAt.Time
	comment.CreatedAt = &created
	updated := node.UpdatedAt.Time
	comment.UpdatedAt = &updated

	return comment
}

func idToString(id githubv4.ID) string {
	switch v := id.(type) {
	case nil:
		return ""
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}
