// This application requires the following environment variables to be set:
// - GITLAB_TOKEN: The token used for authenticating with the GitLab API.
// - GITLAB_URL: The URL of the GitLab instance.
// - GITLAB_BRANCH: The branch in the GitLab repository to interact with.
// - GITLAB_PATH: The path within the GitLab repository.
// - GITLAB_FILE: The specific file within the GitLab repository.

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/xanzy/go-gitlab"
	"k8s.io/client-go/rest"
)

// Define Errors
var (
	ErrTextRecordAlreadyExists = errors.New("txt record already exists")
	ErrTextRecordsDoNotExist   = errors.New("txt records do not exist")
	ErrTextRecordDoesNotExist  = errors.New("txt record does not exist")
	ErrACMEBotContentNotFound  = errors.New("ACME-BOT comments not found")

	ErrGitlabBranchNotDefined = errors.New("GITLAB_BRANCH not defined in environment variables")
	ErrGitlabPathNotDefined   = errors.New("GITLAB_PATH not defined in environment variables")
	ErrGitlabFileNotDefined   = errors.New("GITLAB_FILE not defined in environment variables")
	ErrGitlabTokenNotDefined  = errors.New("GITLAB_TOKEN not defined in environment variables")
	ErrGitlabURLNotDefined    = errors.New("GITLAB_URL not defined in environment variables")
)

var (
	timeToSleepBeforeMergeRequestCheck = 30 * time.Second

	// GroupName is the name of the group that the webhook is running in
	GroupName = os.Getenv("GROUP_NAME")

	// SecretRefName is the name of the secret that contains the configuration
	SecretRefName = os.Getenv("SECRET_REF_NAME")
)

// Creates a target branch if it does not exist
func CreateBranch(git *gitlab.Client, projectPath string, branch string, ref string) error {
	// Skip creating the branch if it already exists
	_, _, err := git.Branches.GetBranch(projectPath, branch)
	if err == nil {
		slog.Info("branch already exists", "branch", branch)
		return nil
	}

	slog.Info("creating branch", "branch", branch)

	cb := &gitlab.CreateBranchOptions{
		Branch: gitlab.Ptr(branch),
		Ref:    gitlab.Ptr(ref),
	}

	_, _, err = git.Branches.CreateBranch(projectPath, cb)
	return err
}

// Creates a merge request and auto-approves it and merges it
func Merge(git *gitlab.Client, projectPath string, sourceBranch string, targetBranch string, title string, description string) error {
	// Create a merge request
	cm := &gitlab.CreateMergeRequestOptions{
		Title:        gitlab.Ptr(title),
		Description:  gitlab.Ptr(description),
		SourceBranch: gitlab.Ptr(sourceBranch),
		TargetBranch: gitlab.Ptr(targetBranch),
	}
	mr, _, err := git.MergeRequests.CreateMergeRequest(projectPath, cm)
	if err != nil {
		return err
	}

	slog.Info("merge request created", "id", mr.IID, "sleeping for some time before approval", timeToSleepBeforeMergeRequestCheck)
	time.Sleep(timeToSleepBeforeMergeRequestCheck)

	// Approve the merge request
	_, _, err = git.MergeRequests.AcceptMergeRequest(projectPath, mr.IID, &gitlab.AcceptMergeRequestOptions{
		ShouldRemoveSourceBranch: gitlab.Ptr(false), // Default should be false but just to be explicit
	})
	if err != nil {
		return err
	}

	return nil
}

func ReadZoneFile(git *gitlab.Client, branch string, path string, filePath string) (string, error) {
	cf := &gitlab.GetFileOptions{
		Ref: gitlab.Ptr(branch),
	}

	f, _, err := git.RepositoryFiles.GetFile(path, filePath, cf)
	if err != nil {
		return "", err
	}

	// Decode the content
	data, err := base64.StdEncoding.DecodeString(f.Content)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func UpdateZoneFile(git *gitlab.Client, branch string, projectPath string, filePath string, content string, cm string) error {
	uf := &gitlab.UpdateFileOptions{
		Branch:        gitlab.Ptr(branch),
		Content:       gitlab.Ptr(content),
		CommitMessage: gitlab.Ptr(cm),
	}
	_, _, err := git.RepositoryFiles.UpdateFile(projectPath, filePath, uf)

	return err
}

// gitSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type gitSolver struct {
	name       string
	txtRecords map[string]string

	gitClient *gitlab.Client
	gitBranch string
	gitPath   string
	gitFile   string

	sync.RWMutex
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (h *gitSolver) Name() string {
	return h.name
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (h *gitSolver) Present(ch *acme.ChallengeRequest) error {
	h.Lock()
	defer h.Unlock()

	// If the TXT record already exists, return early
	if _, ok := h.txtRecords[ch.ResolvedFQDN]; ok {
		return ErrTextRecordAlreadyExists
	}

	// Read the zone file
	content, err := ReadZoneFile(h.gitClient, h.gitBranch, h.gitPath, h.gitFile)
	if err != nil {
		return err
	}

	// Append the new TXT record to the zone file
	record := NewRecord(ch.ResolvedFQDN, ch.Key)
	recordStr, err := record.GenerateTextRecord()
	if err != nil {
		return err
	}

	// Add the TXT record to the zone file
	newContent, err := addTxtRecord(content, recordStr)
	if err != nil {
		return err
	}

	// Update the zone file
	if err := UpdateZoneFile(h.gitClient, h.gitBranch, h.gitPath, h.gitFile, newContent, fmt.Sprintf("Add TXT record: %s", ch.ResolvedFQDN)); err != nil {
		return err
	}

	// Create a merge request
	if err := Merge(h.gitClient, h.gitPath, h.gitBranch, "main", "Add TXT record", "Add TXT record"); err != nil {
		return err
	}

	// Store the TXT record in memory
	h.txtRecords[ch.ResolvedFQDN] = ch.Key
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (h *gitSolver) CleanUp(ch *acme.ChallengeRequest) error {
	h.Lock()
	defer h.Unlock()

	// If the TXT record does not exist, return early
	if _, ok := h.txtRecords[ch.ResolvedFQDN]; !ok {
		return ErrTextRecordDoesNotExist
	}

	record := NewRecord(ch.ResolvedFQDN, ch.Key)
	recordStr, err := record.GenerateTextRecord()
	if err != nil {
		return err
	}

	// Remove the TXT record from the zone file
	content, err := ReadZoneFile(h.gitClient, h.gitBranch, h.gitPath, h.gitFile)
	if err != nil {
		return err
	}
	content, err = removeTxtRecord(content, recordStr)
	if err != nil {
		return err
	}

	// Update the zone file
	if err := UpdateZoneFile(h.gitClient, h.gitBranch, h.gitPath, h.gitFile, content, fmt.Sprintf("Remove TXT record: %s", ch.ResolvedFQDN)); err != nil {
		return err
	}

	// Create a merge request
	if err := Merge(h.gitClient, h.gitPath, h.gitBranch, "main", "Remove TXT record", "Remove TXT record"); err != nil {
		return err
	}

	// Finally, remove the TXT record from memory
	delete(h.txtRecords, ch.ResolvedFQDN)

	return nil
}

// addTxtRecord adds a new TXT record string to the given content and returns the updated content.
func addTxtRecord(content string, recordStr string) (string, error) {
	reToCompile := `; ACME-BOT-END`
	re, err := regexp.Compile(reToCompile)
	if err != nil {
		return "", err
	}

	newText := fmt.Sprintf("%s\n; ACME-BOT-END", recordStr)
	return re.ReplaceAllString(content, newText), nil
}

// removeTxtRecord removes the TXT record string from the given content and returns the updated content.
func removeTxtRecord(content string, recordStr string) (string, error) {
	reToCompile := fmt.Sprintf(`%s\n`, recordStr)
	re, err := regexp.Compile(reToCompile)
	if err != nil {
		return "", err
	}

	newText := ""
	return re.ReplaceAllString(content, newText), nil
}

func (h *gitSolver) extractAcmeBotContent(content string) (string, error) {
	const acmeBotCommentPattern = `; ACME-BOT\n([\s\S]*?); ACME-BOT-END`
	re, err := regexp.Compile(acmeBotCommentPattern)
	if err != nil {
		return "", err
	}

	matches := re.FindStringSubmatch(content)
	if len(matches) == 0 {
		return "", ErrACMEBotContentNotFound
	}

	return matches[1], nil
}

func (h *gitSolver) extractTxtRecords(content string) (map[string]string, error) {
	txtRecords := make(map[string]string)

	const recordPattern = `_acme-challenge\.(.*?)\s+TXT\s+"(.*?)"\n`
	re, err := regexp.Compile(recordPattern)
	if err != nil {
		return txtRecords, err
	}

	submatches := re.FindAllStringSubmatch(content, -1)
	if len(submatches) == 0 {
		return txtRecords, ErrTextRecordsDoNotExist
	}

	for _, submatch := range submatches {
		txtRecords[submatch[1]] = submatch[2]
		slog.Info("found txt record", "fqdn", submatch[1], "value", submatch[2])
	}

	return txtRecords, nil
}

// Initialize will be called when the webhook first starts.
func (h *gitSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	slog.Info("initializing git solver")

	// Non-secret fields
	gitBranch := os.Getenv("GITLAB_BRANCH")
	if gitBranch == "" {
		return ErrGitlabBranchNotDefined
	}
	h.gitBranch = gitBranch

	gitPath := os.Getenv("GITLAB_PATH")
	if gitPath == "" {
		return ErrGitlabPathNotDefined
	}
	h.gitPath = gitPath

	gitFile := os.Getenv("GITLAB_FILE")
	if gitFile == "" {
		return ErrGitlabFileNotDefined
	}
	h.gitFile = gitFile

	// Super secret fields
	gitlabToken := os.Getenv("GITLAB_TOKEN")
	if gitlabToken == "" {
		return ErrGitlabTokenNotDefined
	}

	gitlabUrl := os.Getenv("GITLAB_URL")
	if gitlabUrl == "" {
		return ErrGitlabURLNotDefined
	}

	// Create a new git client
	c, err := gitlab.NewClient(string(gitlabToken), gitlab.WithBaseURL(string(gitlabUrl)))
	if err != nil {
		return err
	}

	h.gitClient = c

	// Create the branch if it does not exist
	if err := CreateBranch(h.gitClient, h.gitPath, h.gitBranch, "main"); err != nil {
		return err
	}

	// Read the zone file to check if the ACME-BOT comments are present
	// Returns base64 encoded content
	content, err := ReadZoneFile(h.gitClient, h.gitBranch, h.gitPath, h.gitFile)
	if err != nil {
		return err
	}

	// Extract the ACME-BOT comments from the zone file
	acmeBotContent, err := h.extractAcmeBotContent(content)
	if err != nil {
		return err
	}

	txtRecords, err := h.extractTxtRecords(acmeBotContent)
	if err != nil && err != ErrTextRecordsDoNotExist {
		return err
	}

	h.txtRecords = txtRecords

	slog.Info("git solver initialized")
	return nil
}

func New() webhook.Solver {
	return &gitSolver{
		name:       "git-solver",
		txtRecords: make(map[string]string),
	}
}

func main() {
	if GroupName == "" {
		panic("GROUP_NAME environment variable is required")
	}

	solver := New()
	cmd.RunWebhookServer(GroupName, solver)
}
