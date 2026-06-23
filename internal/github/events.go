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
	Number    int    `json:"number"`
	Head      Ref    `json:"head"`
	Base      Ref    `json:"base"`
	State     string `json:"state"`
	User      PRUser `json:"user"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
}

// PRUser is the author of the pull request.
type PRUser struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
}

// CommitListEntry is one element from
// GET /repos/{owner}/{repo}/pulls/{n}/commits.
// Only the fields needed for AI detection are decoded.
type CommitListEntry struct {
	SHA    string          `json:"sha"`
	Commit CommitDetail    `json:"commit"`
	Author *GitHubAuthor   `json:"author"` // nil when not associated with a GitHub account
}

// CommitDetail holds the git commit object data.
type CommitDetail struct {
	Message string         `json:"message"`
	Author  CommitGitAuthor `json:"author"`
}

// CommitGitAuthor is the git-level author (name + email, not the GitHub login).
type CommitGitAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// GitHubAuthor is the GitHub user associated with the commit (may be nil).
type GitHubAuthor struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
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

// IssueCommentEvent is sent when a comment is created, edited, or deleted on
// an issue or pull request. TASS uses this for slash command processing.
type IssueCommentEvent struct {
	Action       string          `json:"action"` // "created", "edited", "deleted"
	Issue        IssueRef        `json:"issue"`
	Comment      IssueComment    `json:"comment"`
	Repository   Repository      `json:"repository"`
	Installation *InstallationRef `json:"installation"`
}

type IssueRef struct {
	Number      int    `json:"number"`
	PullRequest *struct{} `json:"pull_request"` // non-nil if the issue IS a PR
}

type IssueComment struct {
	ID   int64       `json:"id"`
	Body string      `json:"body"`
	User CommentUser `json:"user"`
}

type CommentUser struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
}
