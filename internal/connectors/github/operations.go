package github

import (
	"sort"
	"strings"
)

const (
	operationPullRequestMetadata      = "pull_request_metadata"
	operationPullRequestFiles         = "pull_request_files"
	operationRepositoryMetadata       = "repository_metadata"
	operationRepositoryIssues         = "repository_issues"
	operationCreateIssue              = "create_issue"
	operationCreatePullRequestComment = "create_pull_request_comment"
	operationCreateCheckRun           = "create_check_run"
)

var defaultOperations = []string{
	operationPullRequestMetadata,
	operationPullRequestFiles,
	operationRepositoryMetadata,
	operationRepositoryIssues,
}

var defaultReadPermissions = map[string]string{
	"contents":      "read",
	"issues":        "read",
	"pull_requests": "read",
}

var supportedOperations = map[string]struct{}{
	operationPullRequestMetadata:      {},
	operationPullRequestFiles:         {},
	operationRepositoryMetadata:       {},
	operationRepositoryIssues:         {},
	operationCreateIssue:              {},
	operationCreatePullRequestComment: {},
	operationCreateCheckRun:           {},
}

func normalizeOperations(operations []string) []string {
	normalized := make([]string, 0, len(operations))
	seen := make(map[string]struct{}, len(operations))
	for _, operation := range operations {
		trimmed := strings.TrimSpace(operation)
		if trimmed == "" {
			continue
		}
		if _, ok := supportedOperations[trimmed]; !ok {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func permissionsForOperation(operation string, readPermissions map[string]string) map[string]string {
	switch operation {
	case operationCreateIssue:
		return map[string]string{"issues": "write"}
	case operationCreatePullRequestComment:
		return map[string]string{"issues": "write"}
	case operationCreateCheckRun:
		return map[string]string{"checks": "write"}
	default:
		if len(readPermissions) == 0 {
			return clonePermissions(defaultReadPermissions)
		}
		return clonePermissions(readPermissions)
	}
}

func permissionScopeKey(permissions map[string]string) string {
	if len(permissions) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(permissions))
	for key := range permissions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+permissions[key])
	}
	return strings.Join(parts, ",")
}

func clonePermissions(permissions map[string]string) map[string]string {
	if len(permissions) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(permissions))
	for key, value := range permissions {
		cloned[key] = value
	}
	return cloned
}
