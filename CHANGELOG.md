# Changelog

## [0.12.0](https://github.com/compliance-framework/plugin-github-repositories/compare/v0.11.0...v0.12.0) (2026-10-30)


### Features

* GitHub App authentication ([#43](https://github.com/compliance-framework/plugin-github-repositories/issues/43)) ([65774a2](https://github.com/compliance-framework/plugin-github-repositories/commit/65774a2cb6fe069f3652e978904c976670fae349))


### Bug Fixes

* **deps:** build with the go1.26.10 toolchain so Renovate can ship Go security fixes ([#45](https://github.com/compliance-framework/plugin-github-repositories/issues/45)) ([2d7eded](https://github.com/compliance-framework/plugin-github-repositories/commit/2d7eded4c7c49b2dea8aeeec7f8097975258e722))

## [0.11.0](https://github.com/compliance-framework/plugin-github-repositories/compare/v0.10.0...v0.11.0) (2026-10-28)


### ⚠ BREAKING CHANGES

* **deps:** `UsersService.Unsuspend` now takes an `UnsuspendUserRequest` body argument.
    - refactor!: Pass repository creation by value
    ([#&#8203;4616](https://redirect.github.com/google/go-github/issues/4616))
    `RepositoriesService.Create` now requires a
    `CreateRepositoryRequest` value instead of a `*Repository`.
    - refactor!: Rename `LockIssueOptions`,
    `PullRequestBranchUpdateOptions`, and `UserSuspendOptions` to
    `...Request` and pass them by value
    ([#&#8203;4612](https://redirect.github.com/google/go-github/issues/4612))
    `LockIssueOptions`, `PullRequestBranchUpdateOptions`,
    and `UserSuspendOptions` are renamed to `LockIssueRequest`,
    `UpdatePullRequestBranchRequest`, and `SuspendUserRequest` and are
    passed by value to `IssuesService.Lock`,
    `PullRequestsService.UpdateBranch`, and `UsersService.Suspend`;
    `LockIssueRequest.LockReason` is now `*string`.
    - refactor!: Pass the Projects v2 item body types by value and rename
    them to `...Request`
    ([#&#8203;4609](https://redirect.github.com/google/go-github/issues/4609))
    `AddProjectItemOptions` and `UpdateProjectItemOptions`
    are renamed to `AddProjectItemRequest` and `UpdateProjectItemRequest`
    and passed by value; `AddProjectItemRequest.Type` is no longer a
    pointer; `UpdateProjectItemOptions.Archived` is removed.
    - refactor!: Rename `RepositoryCreateForkOptions` and
    `RepositoryAddCollaboratorOptions` to `...Request` and pass them by
    value
    ([#&#8203;4607](https://redirect.github.com/google/go-github/issues/4607))
    `RepositoryCreateForkOptions` and
    `RepositoryAddCollaboratorOptions` are renamed to `CreateForkRequest`
    and `AddCollaboratorRequest`; `RepositoriesService.CreateFork` and
    `RepositoriesService.AddCollaborator` now take them by value instead of
    by pointer; `CreateForkRequest.Organization`, `CreateForkRequest.Name`,
    `CreateForkRequest.DefaultBranchOnly` and
    `AddCollaboratorRequest.Permission` are now pointers.
    - refactor!: Pass the Teams body types by value and rename them to
    `...Request`
    ([#&#8203;4606](https://redirect.github.com/google/go-github/issues/4606))
    `TeamAddTeamMembershipOptions`,
    `TeamAddTeamRepoOptions` and `TeamProjectOptions` are renamed to
    `AddTeamMembershipRequest`, `AddTeamRepoRequest` and
    `AddTeamProjectRequest`; `TeamsService.AddTeamMembershipByID`,
    `AddTeamMembershipBySlug`, `AddTeamRepoByID`, `AddTeamRepoBySlug`,
    `AddTeamProjectByID` and `AddTeamProjectBySlug` now take them by value
    instead of by pointer; `AddTeamMembershipRequest.Role` and
    `AddTeamRepoRequest.Permission` are now `*string`.
    - refactor!: Pass the secret scanning body types by value and rename
    them to `...Request`
    ([#&#8203;4548](https://redirect.github.com/google/go-github/issues/4548))
    `SecretScanningAlertUpdateOptions` and
    `SecretScanningPatternConfigsUpdateOptions` are renamed to
    `UpdateSecretScanningAlertRequest` and
    `UpdateSecretScanningPatternConfigsRequest`;
    `SecretScanningService.UpdateAlert`, `UpdatePatternConfigsForEnterprise`
    and `UpdatePatternConfigsForOrg` now take them by value;
    `UpdateSecretScanningAlertRequest.State` is now `*string`.
    - fix!: Match request body fields to the OpenAPI schemas
    ([#&#8203;4581](https://redirect.github.com/google/go-github/issues/4581))
    Many required request body fields are now passed by
    value.
    - fix!: Send credentials only to configured origins
    ([#&#8203;4564](https://redirect.github.com/google/go-github/issues/4564))
    Credentials are sent only to a client's configured API
    and upload origins — every other destination, including a redirect hop,
    goes out unauthenticated. A request body aimed outside those origins is
    refused. `BasicAuthTransport` and `UnauthenticatedRateLimitedTransport`
    gained `AllowedOrigins`, which GitHub Enterprise users must set.
    - refactor!: Pass org invitation requests by value
    ([#&#8203;4551](https://redirect.github.com/google/go-github/issues/4551))
    `OrganizationsService.CreateOrgInvitation` now takes
    `CreateOrgInvitationRequest` (by value);
    `CreateOrgInvitationRequest.TeamID` is now `TeamIDs`.

### Bug Fixes

* **deps:** bump agent to v0.9.3, workflows to v1.7.0 ([#39](https://github.com/compliance-framework/plugin-github-repositories/issues/39)) ([b53f42f](https://github.com/compliance-framework/plugin-github-repositories/commit/b53f42f55711862be4a336eb0f32a432e338c0ea))
* **deps:** bump agent to v0.9.4 ([#42](https://github.com/compliance-framework/plugin-github-repositories/issues/42)) ([d3030e0](https://github.com/compliance-framework/plugin-github-repositories/commit/d3030e0031a6f4eeb8bacfff94acecebfa203b10))
* **deps:** update all non-major dependencies ([#37](https://github.com/compliance-framework/plugin-github-repositories/issues/37)) ([b3768fa](https://github.com/compliance-framework/plugin-github-repositories/commit/b3768fa81c4dacbb49e2c91c3a9a7a261fcf2e00))
* **deps:** update module github.com/google/go-github/v71 to v93 ([#40](https://github.com/compliance-framework/plugin-github-repositories/issues/40)) ([f471139](https://github.com/compliance-framework/plugin-github-repositories/commit/f471139b91601a0691dbaf44a64e5532c62ca1de))
* **deps:** update module golang.org/x/net to v0.62.0 [security] ([#41](https://github.com/compliance-framework/plugin-github-repositories/issues/41)) ([abf3b5a](https://github.com/compliance-framework/plugin-github-repositories/commit/abf3b5a8d784123cbd63a51f87e7802a3dcd31ae))

## [0.10.0](https://github.com/compliance-framework/plugin-github-repositories/compare/v0.9.0...v0.10.0) (2026-10-14)


### Features

* depend on compliance-framework/agent v0.8.0-rc4 ([8d5ac78](https://github.com/compliance-framework/plugin-github-repositories/commit/8d5ac78fb38795f68239f1a308a994a5085d2da9))


### Bug Fixes

* **deps:** bump agent to v0.9.2 ([#36](https://github.com/compliance-framework/plugin-github-repositories/issues/36)) ([7f15c61](https://github.com/compliance-framework/plugin-github-repositories/commit/7f15c61b3f6c226df456ea052b10612098cb6485))
* **deps:** bump compliance-framework/agent to v0.9.1 ([#24](https://github.com/compliance-framework/plugin-github-repositories/issues/24)) ([451c664](https://github.com/compliance-framework/plugin-github-repositories/commit/451c664560ae281432681355b60476b826525145))
* **deps:** update module golang.org/x/crypto to v0.56.0 [security] ([#28](https://github.com/compliance-framework/plugin-github-repositories/issues/28)) ([9eb759d](https://github.com/compliance-framework/plugin-github-repositories/commit/9eb759df16d7ad4f6fd805c3e9f9704092bf8a84))
* **deps:** update security fixes (gomod) [security] ([#35](https://github.com/compliance-framework/plugin-github-repositories/issues/35)) ([540387c](https://github.com/compliance-framework/plugin-github-repositories/commit/540387c901eea1d185b5b16be38d20cdebc98470))
