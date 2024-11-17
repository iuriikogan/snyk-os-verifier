package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

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

// PluginConfig defines configuration for SnykOSVerifier, including severity and CVSS thresholds
type PluginConfig struct {
	Name         string  `json:"name"`
	MaxCvssScore float64 `json:"maxCvssScore"` // Highest acceptable CVSS score
	SnykFilePath string  `json:"snykFilePath"` // Path to the snyk-os.json file
}

// PluginInputConfig wraps PluginConfig for parsing JSON input
type PluginInputConfig struct {
	Config PluginConfig `json:"config"`
}

// Vulnerability represents a single vulnerability entry in snyk-os.json
type Vulnerability struct {
	ID        string  `json:"id"`
	Severity  string  `json:"severity"`
	CvssScore float64 `json:"cvssScore"`
}

// SnykOSResult represents the structure of snyk-os.json
type SnykOSResult struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

func main() {
	skel.PluginMain(pluginName, pluginVersion, VerifyReference, []string{pluginVersion})
}

// VerifyReference is the main verification logic, processing vulnerabilities from snyk-os.json
func VerifyReference(args *skel.CmdArgs, subjectReference common.Reference, referenceDescriptor ocispecs.ReferenceDescriptor, referrerStore referrerstore.ReferrerStore) (*verifier.VerifierResult, error) {

	// Parse the plugin configuration from STDIN
	inputConf := PluginInputConfig{}
	if err := json.Unmarshal(args.StdinData, &inputConf); err != nil {
		return nil, fmt.Errorf("failed to parse stdin for the input: %v", err)
	}
	config := inputConf.Config

	// Load snyk-os.json from specified path in configuration
	snykData, err := loadSnykOSData(config.SnykFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load snyk-os.json: %v", err)
	}

	// Verify each vulnerability against severity and CVSS thresholds
	for _, vuln := range snykData.Vulnerabilities {
		if vuln.CvssScore > config.MaxCvssScore {
			return &verifier.VerifierResult{
				Name:      config.Name,
				IsSuccess: false,
				Message:   fmt.Sprintf("Denied due to vulnerability %s with severity %s and CVSS score %.1f", vuln.ID, vuln.CvssScore),
				Extensions: map[string]interface{}{
					"vulnerabilityID": vuln.ID,
					"severity":        vuln.Severity,
					"cvssScore":       vuln.CvssScore,
				},
			}, nil
		}
	}

	return &verifier.VerifierResult{
		Name:      config.Name,
		IsSuccess: true,
		Message:   fmt.Sprintf("Verification successful: no vulnerabilities found with CVSS scores higher than %v", config.MaxCvssScore),
	}, nil
}

// loadSnykOSData reads and unmarshals the snyk-os.json file
func loadSnykOSData(filepath string) (*SnykOSResult, error) {
	fileData, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var snykData SnykOSResult
	if err := json.Unmarshal(fileData, &snykData); err != nil {
		return nil, fmt.Errorf("failed to parse snyk-os.json: %w", err)
	}

	return &snykData, nil
}
