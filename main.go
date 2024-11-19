package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/opencontainers/go-digest"
	"github.com/ratify-project/ratify/pkg/common"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	"github.com/ratify-project/ratify/pkg/referrerstore"
	"github.com/ratify-project/ratify/pkg/verifier"
	"github.com/ratify-project/ratify/pkg/verifier/plugin/skel"
)

// Plugin identification constants
const (
	pluginName    = "snyk-os"
	pluginVersion = "1.0.0"
)

// PluginConfig defines configuration for max CVSS score thresholds
type PluginConfig struct {
	MaxCvssScore float64 `json:"maxCvssScore"`
}

// PluginInputConfig wraps PluginConfig for parsing JSON input
type PluginInputConfig struct {
	Config PluginConfig `json:"config"`
}

// CVSSDetails represents CVSS details for a vulnerability
type CVSSDetails struct {
	Assigner        string  `json:"assigner"`
	Severity        string  `json:"severity"`
	CVSSv3Vector    string  `json:"cvssV3Vector"`
	CVSSv3BaseScore float64 `json:"cvssV3BaseScore"`
}

// Reference represents a reference URL for a vulnerability
type Reference struct {
	URL   string `json:"url"`
	Title string `json:"title"`
}

// Vulnerability represents a single vulnerability entry in snyk-os.json
type Vulnerability struct {
	ID             string        `json:"id"`
	Title          string        `json:"title"`
	Severity       string        `json:"severity"`
	CVSSScore      float64       `json:"cvssScore"`
	CVSSDetails    []CVSSDetails `json:"cvssDetails"`
	References     []Reference   `json:"references"`
	ModuleName     string        `json:"moduleName"`
	FixedIn        []string      `json:"fixedIn"`
	UpgradePath    []string      `json:"upgradePath"`
	PackageManager string        `json:"packageManager"`
}

// SnykOS represents the structure of snyk-os.json
type SnykOS struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Main function to execute plugin logic using skel.PluginMain
func main() {
	// Set up structured logging with slog
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Run the plugin main logic
	skel.PluginMain(pluginName, pluginVersion, VerifyReference, []string{pluginVersion})
}

// VerifyReference processes vulnerabilities from snyk-os.json
func VerifyReference(args *skel.CmdArgs, subjectReference common.Reference, referenceDescriptor ocispecs.ReferenceDescriptor, referrerStore referrerstore.ReferrerStore) (*verifier.VerifierResult, error) {
	ctx := context.Background()

	// Parse the plugin configuration from STDIN
	inputConf := PluginInputConfig{}
	if err := json.Unmarshal(args.StdinData, &inputConf); err != nil {
		slog.Error("failed to parse stdin for the input", "error", err)
		return nil, fmt.Errorf("failed to parse stdin for the input: %v", err)
	}
	config := inputConf.Config

	// Pull the snyk-os.json by SubjectReference from the referrerStore
	snykData, err := loadSnykOSData(ctx, subjectReference, referrerStore)
	if err != nil {
		slog.Error("failed to load snyk-os.json", "error", err)
		return nil, fmt.Errorf("failed to load snyk-os.json: %v", err)
	}

	// Verify each vulnerability against severity and CVSS thresholds
	for _, vuln := range snykData.Vulnerabilities {
		if vuln.CVSSScore > config.MaxCvssScore {
			slog.Info("vulnerability denied due to CVSS score exceeding threshold",
				"vulnerabilityID", vuln.ID, "cvssScore", vuln.CVSSScore)

			return &verifier.VerifierResult{
				Name:      pluginName,
				IsSuccess: false,
				Message:   fmt.Sprintf("Denied due to vulnerability %s with CVSS score %.1f", vuln.ID, vuln.CVSSScore),
				Extensions: map[string]interface{}{
					"vulnerabilityID": vuln.ID,
					"cvssScore":       vuln.CVSSScore,
				},
			}, nil
		}
	}

	slog.Info("verification successful: no vulnerabilities exceed the configured CVSS threshold")
	return &verifier.VerifierResult{
		Name:      pluginName,
		IsSuccess: true,
		Message:   "Verification successful: no vulnerabilities exceed the configured CVSS threshold",
	}, nil
}

// loadSnykOSData reads and unmarshals the snyk-os.json file from the referrer store
func loadSnykOSData(ctx context.Context, subjectReference common.Reference, referrerStore referrerstore.ReferrerStore) (*SnykOS, error) {
	// Retrieve the list of referrers for the subject reference
	referrers, err := referrerStore.ListReferrers(ctx, subjectReference, nil, "", nil)
	if err != nil {
		slog.Error("failed to list referrers", "error", err)
		return nil, fmt.Errorf("failed to list referrers: %w", err)
	}

	// Locate the snyk-os.json artifact in the referrers
	var artifactDigest digest.Digest
	for _, ref := range referrers.Referrers {
		if ref.ArtifactType == "application/vnd.snyk-os.json" {
			artifactDigest = ref.Digest
			break
		}
	}

	if artifactDigest == "" {
		slog.Error("snyk-os.json artifact not found")
		return nil, fmt.Errorf("snyk-os.json artifact not found")
	}

	// Fetch the artifact content
	artifactContent, err := referrerStore.GetBlobContent(ctx, subjectReference, artifactDigest)
	if err != nil {
		slog.Error("failed to get snyk-os.json content", "error", err)
		return nil, fmt.Errorf("failed to get snyk-os.json content: %w", err)
	}

	// Unmarshal the JSON content into the SnykOS struct
	var snykData SnykOS
	if err := json.Unmarshal(artifactContent, &snykData); err != nil {
		slog.Error("failed to parse snyk-os.json", "error", err)
		return nil, fmt.Errorf("failed to parse snyk-os.json: %w", err)
	}

	return &snykData, nil
}
