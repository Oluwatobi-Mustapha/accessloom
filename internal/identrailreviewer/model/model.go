package model

type Finding struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	Confidence     float64  `json:"confidence"`
	RuleID         string   `json:"rule_id"`
	Summary        string   `json:"summary"`
	Rationale      string   `json:"rationale"`
	File           string   `json:"file"`
	Line           int      `json:"line"`
	Recommendation string   `json:"recommendation"`
	References     []string `json:"references,omitempty"`
}

type ReviewResult struct {
	Reviewer string            `json:"reviewer"`
	Version  string            `json:"version"`
	Mode     string            `json:"mode"`
	Target   string            `json:"target"`
	Number   int               `json:"number"`
	Status   string            `json:"status"`
	Summary  string            `json:"summary"`
	Findings []Finding         `json:"findings"`
	Abstain  []string          `json:"abstentions,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type ChangedFile struct {
	Filename string `json:"filename"`
	Status   string `json:"status"`
}

type PullRequestEvent struct {
	PullRequest PullRequest `json:"pull_request"`
}

type PullRequest struct {
	Number int     `json:"number"`
	Title  string  `json:"title"`
	Body   string  `json:"body"`
	Labels []Label `json:"labels"`
}

type IssueEvent struct {
	Issue Issue `json:"issue"`
}

type Issue struct {
	Number int     `json:"number"`
	Title  string  `json:"title"`
	Body   string  `json:"body"`
	Labels []Label `json:"labels"`
}

type Label struct {
	Name string `json:"name"`
}
