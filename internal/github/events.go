package github

// Event types and payload structs for GitHub webhook events.
// Only the fields TASS needs — no giant auto-generated SDK types.

// PullRequestEvent is sent when a PR is opened, synchronized, closed, etc.
type PullRequestEvent struct {
	Action      string      `json:"action"`
	Number      int         `json:"number"`
	PullRequest PullRequest `json:"pull_request"`
	Repository  Repository  `json:"repository"`
	Installation *InstallationRef `json:"installation"`
}

type PullRequest struct {
	Number int    `json:"number"`
	Head   Ref    `json:"head"`
	Base   Ref    `json:"base"`
	State  string `json:"state"`
}

type Ref struct {
	SHA  string `json:"sha"`
	Ref  string `json:"ref"` // branch name
	Repo RepoRef `json:"repo"`
}

type RepoRef struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
}

// Repository is the repo field in most webhook payloads.
type Repository struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
}

// InstallationEvent is sent when the app is installed or uninstalled.
// The Repositories field lists repos selected by the user on install.
type InstallationEvent struct {
	Action       string               `json:"action"`
	Installation InstallationPayload  `json:"installation"`
	Repositories []InstallationRepo   `json:"repositories"`
}

// InstallationRepo is a repo entry in the installation.created event.
type InstallationRepo struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}

type InstallationPayload struct {
	ID      int64   `json:"id"`
	Account Account `json:"account"`
}

type Account struct {
	Login string `json:"login"`
	Type  string `json:"type"` // "Organization" or "User"
}

// InstallationRef appears inside other events to identify the installation.
type InstallationRef struct {
	ID int64 `json:"id"`
}
