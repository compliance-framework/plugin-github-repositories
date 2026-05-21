# Repository Dependency Health Evidence Design

## Purpose

This design defines how `plugin-github-repositories` can collect direct dependency health facts for a monitored GitHub repository, and how CCF policies can turn those facts into evidence.

The first target use case is a CRA-oriented demo:

> For repository `ccf/api`, CCF can show that direct dependencies are being tracked, that some dependencies show maintenance risk, and that the organization has evidence to support review, remediation, or replacement planning.

The feature is intended to demonstrate third-party component due diligence. It should not claim that upstream dependency repositories are controlled by the assessed organization.

## Scope

### In Scope

- Parse direct dependencies from `go.mod`.
- Ignore transitive and indirect dependencies.
- Resolve obvious GitHub-hosted module paths, such as `github.com/org/repo`.
- Collect public/free GitHub metadata for each resolved dependency repository.
- Collect dependency license and SBOM visibility facts where public GitHub APIs expose them.
- Expose dependency facts to policies as part of the repository evaluation data.
- Add a small number of policy examples that demonstrate how dependency health evidence can be produced.

### Out of Scope For The First Version

- Transitive dependency parsing.
- Vulnerability lookup.
- Go-specific health scoring.
- Go module version correctness checks.
- Private upstream repository access.
- Non-GitHub repository health collection.
- Hardcoded compliance scoring in the plugin.
- Treating every unresolved dependency as unhealthy.

## Design Principle

The plugin collects facts. Policies decide what those facts mean.

The plugin should answer:

> What direct dependencies does this repository declare, and what public maintenance signals are visible for each dependency?

Policies should answer:

> Given configured thresholds and organizational expectations, which dependencies are healthy, stale, unknown, or require review?

## Data Ownership

### Plugin-Owned Responsibilities

The plugin is responsible for collection and normalization.

It should:

- Fetch `go.mod` from the monitored repository's default branch.
- Parse only direct `require` dependencies.
- Ignore dependencies marked with `// indirect`.
- Normalize each dependency into a generic dependency data model.
- Resolve dependencies hosted at `github.com/org/repo`.
- Collect public GitHub repository health facts for resolved dependencies.
- Collect license metadata for resolved dependency repositories.
- Attempt to collect dependency repository SBOM metadata for resolved dependency repositories.
- Preserve collection errors as data where possible.
- Avoid failing the entire repository evaluation when one dependency cannot be resolved or inspected.

The plugin should not:

- Decide whether a dependency is compliant.
- Hardcode age thresholds.
- Hardcode PR staleness thresholds.
- Treat lack of releases, workflows, or permissions as automatic failure.
- Create CRA-specific conclusions directly in Go code.

### Policy-Owned Responsibilities

Policies are responsible for interpretation.

Policies should:

- Apply thresholds from policy input.
- Decide which signals are warnings, failures, or informational findings.
- Generate CCF evidence for the assessed repository.
- Include the dependency name, version, upstream URL, observed value, and threshold in evidence output.
- Distinguish unhealthy dependencies from dependencies with unknown health.
- Distinguish missing dependency SBOM evidence from collection failures.
- Evaluate dependency licenses using policy-owned allowed or banned license lists.

Policies should not:

- Depend on Go-specific parser details when a generic dependency field is available.
- Assume every dependency has a GitHub repository.
- Assume every healthy project has frequent releases.
- Assume every project uses GitHub Actions.
- Assume every public dependency repository exposes an SBOM.

## Dependency Policy Input Model

Dependency facts are collected as a repository-scoped list internally, but dependency policy bundles should be evaluated once per dependency. Policies should not iterate over `input.dependencies`; they should evaluate the single dependency in `input.dependency`.

Conceptual shape:

```json
{
  "repository": {
    "organization": "ccf",
    "name": "api",
    "full_name": "ccf/api",
    "url": "https://github.com/ccf/api"
  },
  "dependency": {
      "name": "github.com/example/lib",
      "ecosystem": "go",
      "source_file": "go.mod",
      "direct": true,
      "declared_version": "v1.2.3",
      "repository": {
        "provider": "github",
        "owner": "example",
        "name": "lib",
        "url": "https://github.com/example/lib",
        "resolved": true
      },
      "health": {
        "repository_archived": false,
        "latest_release": {
          "tag": "v1.3.0",
          "published_at": "2026-01-10T00:00:00Z"
        },
        "latest_commit": {
          "sha": "abc123",
          "committed_at": "2026-04-15T00:00:00Z"
        },
        "workflows": {
          "count": 3,
          "latest_default_branch_run": {
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-04-16T00:00:00Z"
          }
        },
        "pull_requests": {
          "open_count": 12,
          "oldest_open_created_at": "2025-09-01T00:00:00Z",
          "recent_closed_count": 20,
          "median_days_to_close": 8,
          "median_hours_to_first_interaction": 14
        }
      },
      "supply_chain": {
        "license": {
          "spdx_id": "MIT",
          "name": "MIT License",
          "url": "https://api.github.com/licenses/mit",
          "collected": true
        },
        "sbom": {
          "available": true,
          "package_count": 42,
          "spdx_id": "SPDXRef-DOCUMENT",
          "spdx_version": "SPDX-2.3",
          "creation_info_created": "2026-01-10T00:00:00Z",
          "collected": true
        }
      },
      "collection_status": {
        "dependency_parsed": true,
        "repository_resolved": true,
        "health_collected": true,
        "license_collected": true,
        "sbom_collected": true,
        "errors": []
      }
  },
  "policy_data": {}
}
```

This structure is intentionally generic. Go is only the first source parser.

## First Version Dependency Parsing

The first version should only parse direct dependencies from `go.mod`.

Example:

```go
require (
	github.com/example/lib v1.2.3
	github.com/example/indirect v0.4.0 // indirect
)
```

Expected result:

- Include `github.com/example/lib`.
- Exclude `github.com/example/indirect`.

Single-line direct requirements should also be supported:

```go
require github.com/example/lib v1.2.3
```

The parser should record:

- module path
- declared version
- source file
- ecosystem
- whether it is direct

The parser should not perform Go module health checks in the first version.

## Repository Resolution

The first resolver should handle obvious GitHub module paths:

```text
github.com/{owner}/{repo}
```

For example:

```text
github.com/google/go-github/v71
```

Should resolve to:

```text
owner: google
repo: go-github
url: https://github.com/google/go-github
```

If a dependency cannot be resolved to GitHub, the plugin should still emit the dependency with:

```json
{
  "repository": {
    "resolved": false
  },
  "collection_status": {
    "repository_resolved": false
  }
}
```

Unresolved dependencies are useful evidence for visibility gaps, but they should not be treated as failures by the plugin.

## Health Signals Collected By The Plugin

For each resolved GitHub dependency repository, the plugin should collect public/free signals where available.

### Repository Metadata

- repository exists
- repository URL
- default branch
- archived status
- disabled status, if available

### Release Activity

- latest release tag
- latest release published date
- no release found, if applicable

No release should be represented as data, not as a collection failure.

### Commit Activity

- latest commit on default branch
- latest commit date

### Workflow Activity

- workflow count
- latest workflow run on default branch
- latest workflow run status
- latest workflow run conclusion
- latest workflow run creation date

Missing or inaccessible Actions data should be represented as unknown or unavailable.

### License Metadata

The plugin should collect dependency repository license metadata from the resolved GitHub repository when available.

Suggested facts:

- SPDX license ID
- license name
- license URL
- whether license collection succeeded

An absent or unknown license should be represented as data, not as a collection failure.

The plugin should not decide which licenses are allowed or banned.

### SBOM Metadata

The plugin should attempt to collect the dependency repository SBOM using GitHub's dependency graph SBOM endpoint for each resolved dependency repository.

Suggested facts:

- whether an SBOM was available
- package count
- SPDX document ID
- SPDX version
- creation timestamp, when present
- collection status and any permission or availability error

The first version should not store the full dependency SBOM for every dependency unless needed. A summary is enough for policy checks and keeps evidence payloads smaller.

Missing or inaccessible SBOM data should be represented as unknown or unavailable. It should not fail the parent repository evaluation.

### Pull Request Staleness

The first version should collect enough data for policies to reason about PR staleness without requiring deep analysis.

Suggested facts:

- open PR count
- oldest open PR creation date
- recent closed PR count within a bounded lookback window
- median days to close recent closed PRs
- median hours to first interaction on recently closed PRs

The plugin should keep the collection bounded to reduce GitHub API usage.

Suggested initial bounds:

- first 100 open PRs
- first 100 recently closed PRs
- closed PR lookback controlled by plugin config or a conservative default

## Collection Status

Each dependency should carry collection status.

This is important because unresolved or inaccessible dependencies are different from unhealthy dependencies.

Example statuses:

```json
{
  "dependency_parsed": true,
  "repository_resolved": true,
  "health_collected": false,
  "errors": [
    {
      "scope": "workflows",
      "message": "actions metadata unavailable"
    }
  ]
}
```

The plugin should continue evaluating the parent repository when dependency health collection is partial.

## Policy Design

The initial policy set should be small and demo-focused.

The goal is to show that dependency facts can produce meaningful repository evidence, not to define a complete CRA compliance profile.

These policies should be shipped as a separate opt-in policy collection, not as part of the default `plugin-github-repositories-policies` bundle. The default policy bundle should remain focused on broadly applicable repository controls such as branch protection, workflows, releases, SBOM presence, secret scanning, and access control.

Recommended repository name:

```text
plugin-github-repositories-dependency-policies
```

Alternative CRA-focused name:

```text
plugin-github-repositories-cra-dependency-policies
```

The preferred name is `plugin-github-repositories-dependency-policies` because the expected input data is produced by `plugin-github-repositories`, while the policy domain is dependency health and supply-chain visibility. CRA-specific behavior can be expressed through policy input, profiles, or later policy packages without coupling the whole repository name to CRA.

The existing `plugin-github-repositories-policies` repository uses one Rego file per policy, paired with a `_test.rego` file. Policies expose:

- `package compliance_framework.<policy_name>`
- `title`
- `description`
- optional `remarks`
- optional `skip_reason`
- `risk_templates`
- `violation[{"id": "...", "remarks": "..."}]`

Dependency policies should follow the same pattern. Risk templates should use `violation_ids` when one policy has multiple violation IDs and the risks need to bind to specific outcomes.

### Policy Input

Thresholds should come from policy input.

Example:

```json
{
  "dependency_health": {
    "max_days_since_release": 365,
    "max_days_since_commit": 180,
    "max_open_prs": 50,
    "max_oldest_open_pr_age_days": 180,
    "max_median_days_to_close_pr": 30,
    "require_dependency_sbom": false,
    "banned_licenses": ["BUSL-1.1", "SSPL-1.0", "PolyForm-Noncommercial-1.0.0"],
    "allowed_licenses": [],
    "unknown_health_is_violation": false
  }
}
```

Policies should read this via:

```rego
dependency_health_input := object.get(object.get(input, "policy_data", {}), "dependency_health", {})
```

Default thresholds should be conservative and visible in each policy file.

### Policy Files To Add

The first policy set should include six files and six matching test files:

```text
policies/gh_repo_dependency_repository_archived.rego
policies/gh_repo_dependency_repository_archived_test.rego
policies/gh_repo_dependency_activity_stale.rego
policies/gh_repo_dependency_activity_stale_test.rego
policies/gh_repo_dependency_pr_staleness.rego
policies/gh_repo_dependency_pr_staleness_test.rego
policies/gh_repo_dependency_sbom_available.rego
policies/gh_repo_dependency_sbom_available_test.rego
policies/gh_repo_dependency_license_allowed.rego
policies/gh_repo_dependency_license_allowed_test.rego
policies/gh_repo_dependency_health_unknown.rego
policies/gh_repo_dependency_health_unknown_test.rego
```

All six policies should evaluate `input.dependency`. The plugin routes policy bundles whose path contains `dependency` or `dependencies` through dependency-granular evaluation, producing one evidence result per dependency per policy.

Each violation should include dependency-specific `remarks`. Evidence also carries dependency-specific labels so risk acceptance can distinguish one dependency from another.

Recommended remark shape:

```rego
sprintf("Direct dependency %q at version %q has archived upstream repository %q.", [input.dependency.name, input.dependency.declared_version, input.dependency.repository.url])
```

### Policy 1: Archived Dependency Repository

File:

```text
policies/gh_repo_dependency_repository_archived.rego
```

Package:

```rego
package compliance_framework.dependency_repository_archived
```

Flag a direct dependency when its resolved GitHub repository is archived.

This is a strong and easy-to-explain signal.

Suggested violation:

```rego
violation[{"id": "dependency_repository_archived", "remarks": remarks}] if {
  input.dependency.direct == true
  input.dependency.repository.resolved == true
  input.dependency.health.repository_archived == true
  remarks := sprintf("Direct dependency %q at version %q uses archived upstream repository %q.", [input.dependency.name, input.dependency.declared_version, input.dependency.repository.url])
}
```

Suggested title:

```rego
title := "Direct dependency repository is archived"
```

Suggested description:

```rego
description := "Direct dependencies should not rely on archived upstream repositories unless the dependency has been reviewed and accepted. Archived repositories no longer receive normal maintenance signals and may stop receiving security fixes."
```

Suggested risk template:

```json
{
  "name": "Direct dependency uses archived upstream repository",
  "title": "Archived Third Party Component May Stop Receiving Security Maintenance",
  "statement": "A direct dependency whose upstream repository is archived may no longer receive bug fixes, security patches, or maintainer review. Continued use increases the risk that known or future vulnerabilities remain unresolved in the product's dependency chain.",
  "likelihood_hint": "moderate",
  "impact_hint": "high",
  "violation_ids": ["dependency_repository_archived"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1104",
      "title": "Use of Unmaintained Third Party Components",
      "url": "https://cwe.mitre.org/data/definitions/1104.html"
    }
  ],
  "remediation": {
    "title": "Review or replace the archived dependency",
    "description": "Assess whether the archived dependency is still safe to use. Replace it with a maintained alternative, fork and maintain it internally, or document a time-bound risk acceptance.",
    "tasks": [
      { "title": "Identify code paths that use the archived dependency" },
      { "title": "Check whether a maintained replacement exists" },
      { "title": "Plan dependency replacement or internal maintenance ownership" },
      { "title": "Document any temporary risk acceptance with an expiry date" }
    ]
  }
}
```

Evidence should include:

- assessed repository
- dependency module path
- declared version
- upstream repository URL
- archived status

Example evidence statement:

> Repository `ccf/api` declares direct dependency `github.com/example/lib@v1.2.3`. The dependency repository is archived, so this dependency requires review or replacement planning.

### Policy 2: Stale Dependency Activity

File:

```text
policies/gh_repo_dependency_activity_stale.rego
```

Package:

```rego
package compliance_framework.dependency_activity_stale
```

Flag a direct dependency when both release activity and commit activity are stale based on configured thresholds.

Recommended behavior:

- Old release alone should not automatically fail.
- No release should be treated separately from old release.
- Recent commits can offset old release activity for libraries that do not publish frequent GitHub releases.

Suggested violation IDs:

- `dependency_activity_stale`
- `dependency_has_no_activity_signal`

Suggested behavior:

- `dependency_activity_stale`: latest release is older than `max_days_since_release` and latest commit is older than `max_days_since_commit`.
- `dependency_has_no_activity_signal`: no latest release and no latest commit were collected for a resolved dependency repository.
- If release is old but commit is recent, do not violate.
- If release is absent but commit is recent, do not violate.

Suggested title:

```rego
title := "Direct dependency has recent upstream activity"
```

Suggested description:

```rego
description := "Direct dependency repositories should show recent release or commit activity. A dependency with no recent upstream activity may require review to confirm it is still maintained and safe to rely on."
```

Suggested risk templates:

```json
[
  {
    "name": "Direct dependency has stale upstream activity",
    "title": "Stale Third Party Component Maintenance May Delay Security Fixes",
    "statement": "A direct dependency with no recent release and no recent default-branch commit may indicate reduced upstream maintenance. Reduced maintenance can delay security fixes, compatibility updates, and review of reported defects.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["dependency_activity_stale"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1104",
        "title": "Use of Unmaintained Third Party Components",
        "url": "https://cwe.mitre.org/data/definitions/1104.html"
      }
    ],
    "remediation": {
      "title": "Review stale dependency maintenance status",
      "description": "Confirm whether the dependency remains maintained and appropriate for production use. If not, plan replacement or internal maintenance ownership.",
      "tasks": [
        { "title": "Review upstream repository activity and maintainer communications" },
        { "title": "Check whether newer maintained alternatives exist" },
        { "title": "Create a remediation issue for replacement or upgrade" },
        { "title": "Document acceptance rationale if the dependency is intentionally stable" }
      ]
    }
  },
  {
    "name": "Direct dependency has no collected activity signal",
    "title": "Missing Upstream Activity Evidence Limits Dependency Due Diligence",
    "statement": "When no release or commit activity can be collected for a direct dependency, the organization lacks evidence to determine whether the upstream component is actively maintained. This creates a visibility gap in third-party component risk management.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["dependency_has_no_activity_signal"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1059",
        "title": "Incomplete Documentation",
        "url": "https://cwe.mitre.org/data/definitions/1059.html"
      }
    ],
    "remediation": {
      "title": "Record dependency maintenance evidence",
      "description": "Investigate why upstream activity could not be collected and record an alternative maintenance signal or replacement plan.",
      "tasks": [
        { "title": "Verify the dependency source repository" },
        { "title": "Collect an alternative maintenance signal if GitHub data is unavailable" },
        { "title": "Document the dependency review result" }
      ]
    }
  }
]
```

Evidence should include:

- latest release date, if any
- latest commit date, if any
- configured thresholds
- dependency repository URL

### Policy 3: PR Maintenance Staleness

File:

```text
policies/gh_repo_dependency_pr_staleness.rego
```

Package:

```rego
package compliance_framework.dependency_pr_staleness
```

Flag a direct dependency when PR maintenance signals exceed configured thresholds.

Suggested violation IDs:

- `dependency_open_pr_backlog_stale`
- `dependency_pr_close_time_stale`

Suggested behavior:

- `dependency_open_pr_backlog_stale`: open PR count exceeds `max_open_prs` and oldest open PR age exceeds `max_oldest_open_pr_age_days`.
- `dependency_pr_close_time_stale`: median days to close recent closed PRs exceeds `max_median_days_to_close_pr`.
- If PR data is unavailable, this policy should skip or stay silent. Unknown collection belongs to `dependency_health_unknown`.

Suggested title:

```rego
title := "Direct dependency pull requests are maintained within expected thresholds"
```

Suggested description:

```rego
description := "Direct dependency repositories should not show excessive stale pull request backlog or slow pull request closure because those signals may indicate reduced maintainer responsiveness."
```

Suggested risk template:

```json
{
  "name": "Direct dependency has stale pull request maintenance",
  "title": "Low Upstream Maintainer Responsiveness May Delay Dependency Fixes",
  "statement": "A dependency repository with a large stale pull request backlog or slow pull request closure may have reduced maintainer responsiveness. This can delay bug fixes, security patches, and compatibility updates needed by downstream products.",
  "likelihood_hint": "moderate",
  "impact_hint": "moderate",
  "violation_ids": ["dependency_open_pr_backlog_stale", "dependency_pr_close_time_stale"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1104",
      "title": "Use of Unmaintained Third Party Components",
      "url": "https://cwe.mitre.org/data/definitions/1104.html"
    }
  ],
  "remediation": {
    "title": "Review dependency maintainer responsiveness",
    "description": "Assess whether the dependency is still suitable based on upstream maintainer responsiveness and create a tracked remediation or replacement plan where needed.",
    "tasks": [
      { "title": "Review open pull request backlog and maintainer responses" },
      { "title": "Check whether critical fixes are delayed upstream" },
      { "title": "Evaluate maintained alternatives or internal fork ownership" },
      { "title": "Create a remediation issue for dependencies with unacceptable responsiveness" }
    ]
  }
}
```

Evidence should include:

- open PR count
- oldest open PR age
- median days to close, if available
- configured thresholds

Example evidence statement:

> Repository `ccf/api` declares direct dependency `github.com/example/lib@v1.2.3`. The upstream project has 84 open pull requests and the oldest open pull request is 290 days old, exceeding the configured maintenance threshold.

### Policy 4: Dependency SBOM Available

File:

```text
policies/gh_repo_dependency_sbom_available.rego
```

Package:

```rego
package compliance_framework.dependency_sbom_available
```

Flag a direct dependency when dependency SBOM evidence is required and the resolved upstream repository does not expose an SBOM summary.

This policy should be disabled by default for the demo unless `require_dependency_sbom` is set to `true`, because many public repositories will not expose SBOM data through GitHub's dependency graph endpoint.

Suggested violation IDs:

- `dependency_sbom_absent`
- `dependency_sbom_empty`

Suggested behavior:

- If `require_dependency_sbom` is `false`, do not emit violations.
- `dependency_sbom_absent`: dependency is direct and resolved, but `dep.supply_chain.sbom.available` is not true.
- `dependency_sbom_empty`: dependency SBOM is available but package count is zero.
- If SBOM collection failed due to permissions or API availability, leave that to `dependency_health_unknown` unless `require_dependency_sbom` is true.

Suggested title:

```rego
title := "Direct dependency repository exposes SBOM evidence"
```

Suggested description:

```rego
description := "Direct dependencies should expose SBOM evidence when dependency SBOM visibility is required by policy. Dependency SBOMs improve third-party component visibility and support downstream vulnerability response."
```

Suggested risk template:

```json
{
  "name": "Direct dependency SBOM is absent",
  "title": "Missing Dependency SBOM Limits Third Party Component Visibility",
  "statement": "When a direct dependency does not expose SBOM evidence, downstream users have less visibility into that component's own dependency chain. This can slow vulnerability impact analysis and weaken supply chain due diligence for products that rely on the component.",
  "likelihood_hint": "moderate",
  "impact_hint": "moderate",
  "violation_ids": ["dependency_sbom_absent", "dependency_sbom_empty"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1059",
      "title": "Incomplete Documentation",
      "url": "https://cwe.mitre.org/data/definitions/1059.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1104",
      "title": "Use of Unmaintained Third Party Components",
      "url": "https://cwe.mitre.org/data/definitions/1104.html"
    }
  ],
  "remediation": {
    "title": "Review dependency SBOM visibility",
    "description": "Record whether the dependency provides SBOM information or whether alternative component visibility is available through package metadata, internal scanning, or manual review.",
    "tasks": [
      { "title": "Check whether the upstream dependency publishes an SBOM in releases or repository artifacts" },
      { "title": "Scan the consumed dependency version with an internal SBOM generation tool where feasible" },
      { "title": "Document the dependency SBOM visibility result" },
      { "title": "Prefer dependencies with stronger component transparency for high-risk use cases" }
    ]
  }
}
```

Evidence should include:

- dependency module path
- declared version
- upstream repository URL
- SBOM availability
- package count, if available
- `require_dependency_sbom` policy input value

### Policy 5: Dependency License Allowed

File:

```text
policies/gh_repo_dependency_license_allowed.rego
```

Package:

```rego
package compliance_framework.dependency_license_allowed
```

Flag a direct dependency when its collected upstream repository license is banned or, when an allow-list is configured, not present in the allow-list.

This policy should mirror the existing repository/SBOM license policy style, but it should evaluate `input.dependency.supply_chain.license`.

Suggested violation IDs:

- `dependency_banned_license`
- `dependency_license_not_allowed`
- `dependency_license_unknown`

Suggested behavior:

- `dependency_banned_license`: dependency license SPDX ID matches `banned_licenses`.
- `dependency_license_not_allowed`: `allowed_licenses` is non-empty and dependency license SPDX ID is not in it.
- `dependency_license_unknown`: license collection succeeded but SPDX ID is empty or missing.
- If license collection failed due to repository access or API availability, leave that to `dependency_health_unknown`.

Suggested title:

```rego
title := "Direct dependency license is allowed"
```

Suggested description:

```rego
description := "Direct dependencies should use licenses that are acceptable for the repository's distribution and compliance requirements. Banned, unknown, or non-allow-listed licenses require review."
```

Suggested risk template:

```json
{
  "name": "Direct dependency has unacceptable or unknown license",
  "title": "Dependency License Creates Legal or Distribution Risk",
  "statement": "A direct dependency with a banned, unknown, or non-allow-listed license can create legal, commercial, or redistribution risk for the product. License uncertainty also weakens the evidence needed to demonstrate third-party component due diligence.",
  "likelihood_hint": "moderate",
  "impact_hint": "high",
  "violation_ids": ["dependency_banned_license", "dependency_license_not_allowed", "dependency_license_unknown"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1059",
      "title": "Incomplete Documentation",
      "url": "https://cwe.mitre.org/data/definitions/1059.html"
    }
  ],
  "remediation": {
    "title": "Review or replace dependency with unacceptable license",
    "description": "Confirm whether the dependency license is compatible with the repository's use case. Replace the dependency, obtain legal approval, or document an accepted exception where appropriate.",
    "tasks": [
      { "title": "Review the dependency's upstream license file and package metadata" },
      { "title": "Confirm compatibility with product distribution and customer obligations" },
      { "title": "Replace dependencies with unacceptable licenses" },
      { "title": "Document legal approval or risk acceptance for exceptions" },
      { "title": "Add license scanning to prevent recurrence" }
    ]
  }
}
```

Evidence should include:

- dependency module path
- declared version
- upstream repository URL
- collected SPDX ID
- banned or allowed license list used by policy

### Policy 6: Unknown Dependency Health

File:

```text
policies/gh_repo_dependency_health_unknown.rego
```

Package:

```rego
package compliance_framework.dependency_health_unknown
```

Warn when dependency health cannot be collected.

This should support due-diligence evidence without overclaiming risk.

Examples:

- dependency repository cannot be resolved
- dependency repository is not hosted on GitHub
- dependency repository is inaccessible
- workflows are unavailable
- license metadata is unavailable
- SBOM metadata is unavailable

Unknown health should be a warning or informational finding unless the organization's policy says otherwise.

Because the current policy engine models policy outcomes through violations, this policy should be configurable:

- If `unknown_health_is_violation` is `false`, expose a `skip_reason` or no violation.
- If `unknown_health_is_violation` is `true`, emit violations for unresolved or uncollected dependency health.

Suggested violation IDs:

- `dependency_repository_unresolved`
- `dependency_health_not_collected`

Suggested title:

```rego
title := "Direct dependency health is observable"
```

Suggested description:

```rego
description := "Direct dependency health should be observable enough to support third-party component due diligence. Unresolved or inaccessible dependencies create visibility gaps that may require manual review."
```

Suggested risk template:

```json
{
  "name": "Direct dependency health could not be determined",
  "title": "Unknown Third Party Component Health Creates Supply Chain Visibility Gap",
  "statement": "When the source repository or maintenance health of a direct dependency cannot be determined, the organization cannot demonstrate complete due diligence over that third-party component. This may delay vulnerability response and complicate replacement planning when the component becomes risky.",
  "likelihood_hint": "moderate",
  "impact_hint": "moderate",
  "violation_ids": ["dependency_repository_unresolved", "dependency_health_not_collected"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1059",
      "title": "Incomplete Documentation",
      "url": "https://cwe.mitre.org/data/definitions/1059.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1104",
      "title": "Use of Unmaintained Third Party Components",
      "url": "https://cwe.mitre.org/data/definitions/1104.html"
    }
  ],
  "remediation": {
    "title": "Resolve dependency source and maintenance evidence",
    "description": "Determine the upstream source and maintenance status for the dependency, or document why the dependency cannot be evaluated automatically.",
    "tasks": [
      { "title": "Confirm the dependency source repository or package registry metadata" },
      { "title": "Record a manual maintenance review when automatic collection is unavailable" },
      { "title": "Replace dependencies whose source cannot be trusted or verified" },
      { "title": "Document any accepted visibility gap with a review date" }
    ]
  }
}
```

## Policy Work Required

The new policy repository should be bootstrapped with the same conventions as `plugin-github-repositories-policies`.

Recommended repository:

```text
plugin-github-repositories-dependency-policies
```

The policy workspace changes should include:

- Add the six policy files listed above.
- Add one `_test.rego` file per policy.
- Add `README.md` explaining that the policy collection expects `plugin-github-repositories` input with dependency collection enabled.
- Add `Makefile` or equivalent bundle/test workflow matching `plugin-github-repositories-policies`.
- Use `input.dependency` as the policy input surface.
- Use `input.policy_data.dependency_health` for thresholds.
- Include `title`, `description`, and `risk_templates` in every policy.
- Include dependency-specific `remarks` in every violation.
- Add skip tests where data is absent or collection is unavailable.
- Run `opa test policies`.

Minimum test coverage per policy:

- passing case with healthy dependency data
- violation case with one unhealthy dependency
- non-direct dependency ignored
- unresolved or partial collection handled as intended
- policy input threshold override where applicable

## Evidence Relationship Model

The primary assessed subject remains the monitored repository.

Example:

```text
github-repository/ccf/api
```

Each dependency should be referenced in evidence details.

Recommended dependency identifier:

```text
dependency/go/github.com/example/lib
```

The first implementation can keep dependencies nested under repository evaluation data. However, identifiers should be stable enough that dependencies can become first-class inventory items later.

Future inventory item example:

```text
dependency/go/github.com/example/lib@v1.2.3
```

This allows future evidence relationships such as:

```text
github-repository/ccf/api uses dependency/go/github.com/example/lib@v1.2.3
```

## Implementation Shape

When implementation starts, split the plugin code into three conceptual layers.

### 1. Dependency Parser

First implementation:

- `go.mod` parser
- direct dependencies only
- generic output

Future implementations can add parsers for other ecosystems without changing policy shape.

### 2. Repository Resolver

First implementation:

- resolve `github.com/{owner}/{repo}` module paths

Future implementations can add:

- vanity Go import resolution
- npm repository metadata
- PyPI project URLs
- Maven SCM URLs

### 3. Dependency Health Collector

First implementation:

- collect GitHub repository metadata
- latest release
- latest commit
- workflow summary
- PR staleness summary
- license summary
- SBOM summary

The collector should use the existing GitHub client and should treat dependency-level failures as partial dependency collection, not as parent repository evaluation failure.

## Configuration Considerations

The first version can use conservative defaults, but the following plugin-level settings may be useful:

```yaml
dependency_health_enabled: true
dependency_health_max_dependencies: 50
dependency_health_closed_pr_lookback_days: 180
dependency_health_include_unresolved: true
dependency_health_collect_sbom: true
```

Policy thresholds should remain in policy input, not plugin config.

Plugin config should control collection cost and feature enablement.

Policy input should control interpretation.

## CRA Demo Framing

The recommended CRA-oriented framing is:

> The organization maintains visibility into direct third-party software dependencies and monitors public maintenance signals for those dependencies. Dependencies with weak or unknown maintenance signals are tracked for review, remediation, or replacement planning.

Avoid this framing:

> This dependency is CRA-compliant or non-compliant.

The plugin can provide evidence supporting third-party component due diligence, but it should not certify upstream projects.

## First Demo Outcome

The first demo should be able to say:

> For repository `ccf/api`, CCF identified direct dependencies from `go.mod`, resolved the GitHub-hosted upstream repositories, collected public maintenance and supply-chain visibility signals, and produced evidence that selected dependencies require review.

Concrete demo findings could include:

- direct dependency repository is archived
- direct dependency has no recent release and no recent commits
- direct dependency has stale PR maintenance indicators
- direct dependency has unacceptable or unknown license metadata
- direct dependency does not expose SBOM evidence when dependency SBOM visibility is required
- direct dependency health could not be determined

This is enough to prove the capability while keeping the implementation small and the policy behavior explainable.
