package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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

	// Attestation configuration (JSON-encoded strings due to proto map[string]string constraint)
	SBOMAttestationPath   string `mapstructure:"sbom_attestation_path"`
	SBOMAuthorizedSigners string `mapstructure:"sbom_authorized_signers"` // JSON: ["email1", "email2"]
	FileSignerRules       string `mapstructure:"file_signer_rules"`       // JSON: [{"path":..., "attestation_path":..., "authorized_signers":[...]}]
	RequiredWorkflows     string `mapstructure:"required_workflows"`      // JSON: [{"path":..., "attestation_path":..., "authorized_signers":[...]}]
}

// FileSignerRule defines a file path and its authorized signers for attestation verification
type FileSignerRule struct {
	Path              string   `json:"path"`
	AttestationPath   string   `json:"attestation_path"`
	AuthorizedSigners []string `json:"authorized_signers"`
}

// ParsedConfig holds the parsed JSON configuration fields
type ParsedConfig struct {
	SBOMAttestationPath   string
	SBOMAuthorizedSigners []string
	FileSignerRules       []FileSignerRule
	RequiredWorkflows     []FileSignerRule
}

// Parse decodes JSON-encoded configuration fields into structured types
func (c *PluginConfig) Parse() (*ParsedConfig, error) {
	parsed := &ParsedConfig{
		SBOMAttestationPath: c.SBOMAttestationPath,
	}

	if c.SBOMAuthorizedSigners != "" {
		if err := json.Unmarshal([]byte(c.SBOMAuthorizedSigners), &parsed.SBOMAuthorizedSigners); err != nil {
			return nil, fmt.Errorf("invalid sbom_authorized_signers JSON: %w", err)
		}
	}
	if c.FileSignerRules != "" {
		if err := json.Unmarshal([]byte(c.FileSignerRules), &parsed.FileSignerRules); err != nil {
			return nil, fmt.Errorf("invalid file_signer_rules JSON: %w", err)
		}
	}
	if c.RequiredWorkflows != "" {
		if err := json.Unmarshal([]byte(c.RequiredWorkflows), &parsed.RequiredWorkflows); err != nil {
			return nil, fmt.Errorf("invalid required_workflows JSON: %w", err)
		}
	}
	return parsed, nil
}

// AttestationInfo holds the result of parsing and verifying an attestation bundle
type AttestationInfo struct {
	Exists         bool   `json:"exists"`
	Verified       bool   `json:"verified"`
	SignerIdentity string `json:"signer_identity"`
	SignerIssuer   string `json:"signer_issuer"`
	Timestamp      string `json:"timestamp"`
	Error          string `json:"error,omitempty"`
}

// TrackedFileInfo holds information about a tracked file and its attestation
type TrackedFileInfo struct {
	Path              string           `json:"path"`
	Exists            bool             `json:"exists"`
	Attestation       *AttestationInfo `json:"attestation"`
	AuthorizedSigners []string         `json:"authorized_signers"`
}

// WorkflowInfo holds information about a required workflow and its attestation
type WorkflowInfo struct {
	Name              string           `json:"name"`
	Path              string           `json:"path"`
	Exists            bool             `json:"exists"`
	Attestation       *AttestationInfo `json:"attestation"`
	AuthorizedSigners []string         `json:"authorized_signers"`
}

// SBOMAttestationData holds SBOM attestation info and authorized signers for policy evaluation
type SBOMAttestationData struct {
	Attestation       *AttestationInfo `json:"attestation"`
	AuthorizedSigners []string         `json:"authorized_signers"`
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
	OpenPullRequests     []*github.PullRequest                   `json:"pull_requests"`

	// Attestation verification data
	SBOMAttestationData *SBOMAttestationData `json:"sbom_attestation_data,omitempty"`
	TrackedFiles        []*TrackedFileInfo   `json:"tracked_files,omitempty"`
	RequiredWorkflows   []*WorkflowInfo      `json:"required_workflows,omitempty"`
}

type GithubReposPlugin struct {
	Logger hclog.Logger

	config       *PluginConfig
	parsedConfig *ParsedConfig
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

	// Parse JSON-encoded configuration fields
	parsed, err := config.Parse()
	if err != nil {
		l.Logger.Error("Error parsing config", "error", err)
		return nil, err
	}
	l.parsedConfig = parsed

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

			pullRequests, err := l.GatherOpenPullRequests(ctx, repo)
			if err != nil {
				l.Logger.Error("error gathering pull requests", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			// Gather attestation data (non-fatal errors)
			sbomAttestationData, err := l.GatherSBOMAttestation(ctx, repo)
			if err != nil {
				l.Logger.Warn("Error gathering SBOM attestation", "error", err)
			}

			trackedFiles, err := l.GatherTrackedFileAttestations(ctx, repo)
			if err != nil {
				l.Logger.Warn("Error gathering tracked file attestations", "error", err)
			}

			requiredWorkflows, err := l.GatherRequiredWorkflows(ctx, repo)
			if err != nil {
				l.Logger.Warn("Error gathering required workflows", "error", err)
			}

			data := &SaturatedRepository{
				Settings:             repo,
				Workflows:            workflows,
				WorkflowRuns:         workflowRuns,
				ProtectedBranches:    branchNames,
				RequiredStatusChecks: requiredChecks,
				SBOM:                 sbom,
				OpenPullRequests:     pullRequests,
				SBOMAttestationData:  sbomAttestationData,
				TrackedFiles:         trackedFiles,
				RequiredWorkflows:    requiredWorkflows,
			}

			// Uncomment to check the data that is being passed through from
			// the client, as data formats are often slightly different than
			// the raw API endpoints
			jsonData, _ := json.MarshalIndent(data, "", "  ")
			err = os.WriteFile(fmt.Sprintf("./dist/%s.json", repo.GetName()), jsonData, 0o644)
			if err != nil {
				l.Logger.Error("failed to write file", "error", err)
			}
			l.Logger.Debug("Starting policy evaluation", "saturated_repository", string(jsonData))

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

// FetchFileContent retrieves the content of a file from the repository.
// Returns the file content, whether the file exists, and any error.
func (l *GithubReposPlugin) FetchFileContent(ctx context.Context, repo *github.Repository, path string) ([]byte, bool, error) {
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()

	fileContent, _, resp, err := l.githubClient.Repositories.GetContents(ctx, owner, name, path, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return nil, false, nil
		}
		return nil, false, err
	}

	if fileContent == nil {
		return nil, false, nil
	}

	// GetContents returns base64-encoded content
	content, err := base64.StdEncoding.DecodeString(*fileContent.Content)
	if err != nil {
		return nil, true, fmt.Errorf("failed to decode file content: %w", err)
	}

	return content, true, nil
}

// ParseAttestationBundle parses a Sigstore attestation bundle and extracts signer information.
// Supports both Sigstore bundle format and simple DSSE envelope format.
func (l *GithubReposPlugin) ParseAttestationBundle(content []byte) (*AttestationInfo, error) {
	info := &AttestationInfo{
		Exists: true,
	}

	// Try to parse as Sigstore bundle format first
	var bundle struct {
		MediaType            string `json:"mediaType"`
		VerificationMaterial struct {
			Certificate struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificate"`
			TlogEntries []struct {
				IntegratedTime string `json:"integratedTime"`
				LogID          struct {
					KeyID string `json:"keyId"`
				} `json:"logId"`
				CanonicalizedBody string `json:"canonicalizedBody"`
			} `json:"tlogEntries"`
		} `json:"verificationMaterial"`
		DsseEnvelope struct {
			Payload     string `json:"payload"`
			PayloadType string `json:"payloadType"`
			Signatures  []struct {
				Sig   string `json:"sig"`
				KeyID string `json:"keyid"`
			} `json:"signatures"`
		} `json:"dsseEnvelope"`
	}

	if err := json.Unmarshal(content, &bundle); err != nil {
		info.Error = fmt.Sprintf("failed to parse attestation bundle: %v", err)
		return info, nil
	}

	// Check if this looks like a valid bundle
	if bundle.MediaType != "" || len(bundle.VerificationMaterial.TlogEntries) > 0 {
		info.Verified = true // Bundle exists and is parseable

		// Extract timestamp from tlog entry if available
		if len(bundle.VerificationMaterial.TlogEntries) > 0 {
			info.Timestamp = bundle.VerificationMaterial.TlogEntries[0].IntegratedTime
		}

		// Try to extract signer identity from certificate
		if bundle.VerificationMaterial.Certificate.RawBytes != "" {
			// Certificate is base64-encoded DER
			certBytes, err := base64.StdEncoding.DecodeString(bundle.VerificationMaterial.Certificate.RawBytes)
			if err == nil {
				// Parse certificate to extract subject/SAN
				signerInfo := l.extractSignerFromCertificate(certBytes)
				info.SignerIdentity = signerInfo.Identity
				info.SignerIssuer = signerInfo.Issuer
			}
		}

		return info, nil
	}

	// Try parsing as simple DSSE envelope
	var dsse struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}

	if err := json.Unmarshal(content, &dsse); err == nil && dsse.PayloadType != "" {
		info.Verified = len(dsse.Signatures) > 0
		if len(dsse.Signatures) > 0 {
			info.SignerIdentity = dsse.Signatures[0].KeyID
		}
		return info, nil
	}

	info.Error = "unrecognized attestation format"
	return info, nil
}

// signerInfo holds extracted signer information from a certificate
type signerInfo struct {
	Identity string
	Issuer   string
}

// Fulcio OIDC extension OIDs for Sigstore certificates
// See: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
var (
	// OID 1.3.6.1.4.1.57264.1.1 - Issuer (OIDC provider URL)
	oidFulcioIssuer = []int{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	// OID 1.3.6.1.4.1.57264.1.8 - Issuer (v2)
	oidFulcioIssuerV2 = []int{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// extractSignerFromCertificate extracts signer identity from an X.509 certificate.
// For Sigstore/Fulcio certificates, this extracts the OIDC identity from SANs
// and the issuer from Fulcio-specific extensions.
func (l *GithubReposPlugin) extractSignerFromCertificate(certDER []byte) signerInfo {
	info := signerInfo{}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		l.Logger.Debug("Failed to parse X.509 certificate", "error", err)
		return info
	}

	// Extract identity from Subject Alternative Names (SANs)
	// Fulcio certificates store the OIDC identity in SANs
	if len(cert.EmailAddresses) > 0 {
		// Email-based identity (e.g., user@example.com)
		info.Identity = cert.EmailAddresses[0]
	} else if len(cert.URIs) > 0 {
		// URI-based identity (e.g., GitHub Actions OIDC)
		// Format: https://github.com/owner/repo/.github/workflows/workflow.yml@refs/heads/main
		info.Identity = cert.URIs[0].String()
	} else if len(cert.DNSNames) > 0 {
		// DNS-based identity (less common for Sigstore)
		info.Identity = cert.DNSNames[0]
	}

	// Extract issuer from Fulcio-specific extensions
	for _, ext := range cert.Extensions {
		if oidEqual(ext.Id, oidFulcioIssuer) || oidEqual(ext.Id, oidFulcioIssuerV2) {
			// The extension value is typically a UTF8String or IA5String
			// For simplicity, we treat it as a string directly
			info.Issuer = cleanExtensionValue(ext.Value)
			break
		}
	}

	// Fallback: use certificate issuer CN if no Fulcio extension found
	if info.Issuer == "" && len(cert.Issuer.CommonName) > 0 {
		info.Issuer = cert.Issuer.CommonName
	}

	return info
}

// oidEqual compares two OID slices for equality
func oidEqual(a []int, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// cleanExtensionValue removes ASN.1 encoding artifacts from extension values
func cleanExtensionValue(value []byte) string {
	// ASN.1 UTF8String or IA5String typically has a 2-byte header (tag + length)
	// We try to extract the actual string content
	if len(value) > 2 {
		// Check for common ASN.1 string type tags
		tag := value[0]
		if tag == 0x0C || tag == 0x16 || tag == 0x13 { // UTF8String, IA5String, PrintableString
			length := int(value[1])
			if length <= len(value)-2 {
				return string(value[2 : 2+length])
			}
		}
	}
	// Fallback: try to extract printable content
	result := strings.TrimFunc(string(value), func(r rune) bool {
		return r < 32 || r > 126
	})
	// Try to parse as URL to validate
	if _, err := url.Parse(result); err == nil {
		return result
	}
	return string(value)
}

// GatherSBOMAttestation fetches and parses the SBOM attestation file from the repository.
func (l *GithubReposPlugin) GatherSBOMAttestation(ctx context.Context, repo *github.Repository) (*SBOMAttestationData, error) {
	if l.parsedConfig == nil || l.parsedConfig.SBOMAttestationPath == "" {
		return nil, nil
	}

	data := &SBOMAttestationData{
		AuthorizedSigners: l.parsedConfig.SBOMAuthorizedSigners,
	}

	content, exists, err := l.FetchFileContent(ctx, repo, l.parsedConfig.SBOMAttestationPath)
	if err != nil {
		data.Attestation = &AttestationInfo{
			Exists: false,
			Error:  err.Error(),
		}
		return data, nil
	}

	if !exists {
		data.Attestation = &AttestationInfo{
			Exists: false,
		}
		return data, nil
	}

	attestation, err := l.ParseAttestationBundle(content)
	if err != nil {
		data.Attestation = &AttestationInfo{
			Exists: true,
			Error:  err.Error(),
		}
		return data, nil
	}

	data.Attestation = attestation
	return data, nil
}

// GatherTrackedFileAttestations fetches attestations for all configured tracked files.
func (l *GithubReposPlugin) GatherTrackedFileAttestations(ctx context.Context, repo *github.Repository) ([]*TrackedFileInfo, error) {
	if l.parsedConfig == nil || len(l.parsedConfig.FileSignerRules) == 0 {
		return nil, nil
	}

	var trackedFiles []*TrackedFileInfo

	for _, rule := range l.parsedConfig.FileSignerRules {
		fileInfo := &TrackedFileInfo{
			Path:              rule.Path,
			AuthorizedSigners: rule.AuthorizedSigners,
		}

		// Check if the file itself exists
		_, exists, err := l.FetchFileContent(ctx, repo, rule.Path)
		if err != nil {
			l.Logger.Warn("Error checking file existence", "path", rule.Path, "error", err)
			fileInfo.Exists = false
			trackedFiles = append(trackedFiles, fileInfo)
			continue
		}
		fileInfo.Exists = exists

		if !exists {
			trackedFiles = append(trackedFiles, fileInfo)
			continue
		}

		// Fetch the attestation file
		attContent, attExists, err := l.FetchFileContent(ctx, repo, rule.AttestationPath)
		if err != nil {
			fileInfo.Attestation = &AttestationInfo{
				Exists: false,
				Error:  err.Error(),
			}
			trackedFiles = append(trackedFiles, fileInfo)
			continue
		}

		if !attExists {
			fileInfo.Attestation = &AttestationInfo{
				Exists: false,
			}
			trackedFiles = append(trackedFiles, fileInfo)
			continue
		}

		attestation, _ := l.ParseAttestationBundle(attContent)
		fileInfo.Attestation = attestation
		trackedFiles = append(trackedFiles, fileInfo)
	}

	return trackedFiles, nil
}

// GatherRequiredWorkflows checks for the existence of required workflows and their attestations.
func (l *GithubReposPlugin) GatherRequiredWorkflows(ctx context.Context, repo *github.Repository) ([]*WorkflowInfo, error) {
	if l.parsedConfig == nil || len(l.parsedConfig.RequiredWorkflows) == 0 {
		return nil, nil
	}

	var workflows []*WorkflowInfo

	for _, rule := range l.parsedConfig.RequiredWorkflows {
		workflowInfo := &WorkflowInfo{
			Name:              filepath.Base(rule.Path),
			Path:              rule.Path,
			AuthorizedSigners: rule.AuthorizedSigners,
		}

		// Check if the workflow file exists
		_, exists, err := l.FetchFileContent(ctx, repo, rule.Path)
		if err != nil {
			l.Logger.Warn("Error checking workflow existence", "path", rule.Path, "error", err)
			workflowInfo.Exists = false
			workflows = append(workflows, workflowInfo)
			continue
		}
		workflowInfo.Exists = exists

		if !exists {
			workflows = append(workflows, workflowInfo)
			continue
		}

		// Fetch the attestation file
		attContent, attExists, err := l.FetchFileContent(ctx, repo, rule.AttestationPath)
		if err != nil {
			workflowInfo.Attestation = &AttestationInfo{
				Exists: false,
				Error:  err.Error(),
			}
			workflows = append(workflows, workflowInfo)
			continue
		}

		if !attExists {
			workflowInfo.Attestation = &AttestationInfo{
				Exists: false,
			}
			workflows = append(workflows, workflowInfo)
			continue
		}

		attestation, _ := l.ParseAttestationBundle(attContent)
		workflowInfo.Attestation = attestation
		workflows = append(workflows, workflowInfo)
	}

	return workflows, nil
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

	// Add SBOM attestation as subject
	if data.SBOMAttestationData != nil {
		sbomStatus := "not_found"
		if data.SBOMAttestationData.Attestation != nil {
			if !data.SBOMAttestationData.Attestation.Exists {
				sbomStatus = "attestation_missing"
			} else if !data.SBOMAttestationData.Attestation.Verified {
				sbomStatus = "signature_invalid"
			} else {
				sbomStatus = "verified"
			}
		}

		sbomProps := []*proto.Property{
			{Name: "type", Value: "sbom-attestation"},
			{Name: "status", Value: sbomStatus},
		}
		if data.SBOMAttestationData.Attestation != nil && data.SBOMAttestationData.Attestation.SignerIdentity != "" {
			sbomProps = append(sbomProps, &proto.Property{
				Name:  "signer",
				Value: data.SBOMAttestationData.Attestation.SignerIdentity,
			})
		}
		if len(data.SBOMAttestationData.AuthorizedSigners) > 0 {
			sbomProps = append(sbomProps, &proto.Property{
				Name:  "authorized_signers",
				Value: strings.Join(data.SBOMAttestationData.AuthorizedSigners, ","),
			})
		}

		subjects = append(subjects, &proto.Subject{
			Type:        proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier:  fmt.Sprintf("sbom-attestation/%s", data.Settings.GetFullName()),
			Description: "Software Bill of Materials attestation for the repository",
			Props:       sbomProps,
		})
	}

	// Add tracked files as subjects
	for _, tf := range data.TrackedFiles {
		fileStatus := "not_found"
		if tf.Exists {
			if tf.Attestation == nil || !tf.Attestation.Exists {
				fileStatus = "attestation_missing"
			} else if !tf.Attestation.Verified {
				fileStatus = "signature_invalid"
			} else {
				fileStatus = "verified"
			}
		}

		fileProps := []*proto.Property{
			{Name: "type", Value: "tracked-file"},
			{Name: "path", Value: tf.Path},
			{Name: "exists", Value: fmt.Sprintf("%t", tf.Exists)},
			{Name: "status", Value: fileStatus},
		}
		if tf.Attestation != nil && tf.Attestation.SignerIdentity != "" {
			fileProps = append(fileProps, &proto.Property{
				Name:  "signer",
				Value: tf.Attestation.SignerIdentity,
			})
		}
		if len(tf.AuthorizedSigners) > 0 {
			fileProps = append(fileProps, &proto.Property{
				Name:  "authorized_signers",
				Value: strings.Join(tf.AuthorizedSigners, ","),
			})
		}

		subjects = append(subjects, &proto.Subject{
			Type:        proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier:  fmt.Sprintf("tracked-file/%s/%s", data.Settings.GetFullName(), tf.Path),
			Description: fmt.Sprintf("Critical file tracked for signature verification: %s", tf.Path),
			Props:       fileProps,
		})
	}

	// Add required workflows as subjects
	for _, wf := range data.RequiredWorkflows {
		wfStatus := "not_found"
		if wf.Exists {
			if wf.Attestation == nil || !wf.Attestation.Exists {
				wfStatus = "attestation_missing"
			} else if !wf.Attestation.Verified {
				wfStatus = "signature_invalid"
			} else {
				wfStatus = "verified"
			}
		}

		wfProps := []*proto.Property{
			{Name: "type", Value: "required-workflow"},
			{Name: "path", Value: wf.Path},
			{Name: "name", Value: wf.Name},
			{Name: "exists", Value: fmt.Sprintf("%t", wf.Exists)},
			{Name: "status", Value: wfStatus},
		}
		if wf.Attestation != nil && wf.Attestation.SignerIdentity != "" {
			wfProps = append(wfProps, &proto.Property{
				Name:  "signer",
				Value: wf.Attestation.SignerIdentity,
			})
		}
		if len(wf.AuthorizedSigners) > 0 {
			wfProps = append(wfProps, &proto.Property{
				Name:  "authorized_signers",
				Value: strings.Join(wf.AuthorizedSigners, ","),
			})
		}

		subjects = append(subjects, &proto.Subject{
			Type:        proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier:  fmt.Sprintf("required-workflow/%s/%s", data.Settings.GetFullName(), wf.Path),
			Description: fmt.Sprintf("Required workflow tracked for existence and signature verification: %s", wf.Path),
			Props:       wfProps,
		})
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
