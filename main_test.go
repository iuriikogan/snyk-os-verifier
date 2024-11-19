package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ratify-project/ratify/pkg/common"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	"github.com/ratify-project/ratify/pkg/referrerstore"
	"github.com/ratify-project/ratify/pkg/verifier/plugin/skel"
)

type MockReferrerStore struct {
	ListReferrersFunc  func(ctx context.Context, subject common.Reference, opts *referrerstore.ListReferrersOptions, artifactType string, filters []referrerstore.Filter) (*referrerstore.ListReferrersResult, error)
	GetBlobContentFunc func(ctx context.Context, subject common.Reference, digest common.Digest) ([]byte, error)
}

func (m *MockReferrerStore) ListReferrers(ctx context.Context, subject common.Reference, opts *referrerstore.ListReferrersOptions, artifactType string, filters []referrerstore.Filter) (*referrerstore.ListReferrersResult, error) {
	return m.ListReferrersFunc(ctx, subject, opts, artifactType, filters)
}

func (m *MockReferrerStore) GetBlobContent(ctx context.Context, subject common.Reference, digest common.Digest) ([]byte, error) {
	return m.GetBlobContentFunc(ctx, subject, digest)
}

func TestVerifyReference_Success(t *testing.T) {
	mockStore := &MockReferrerStore{
		ListReferrersFunc: func(ctx context.Context, subject common.Reference, opts *referrerstore.ListReferrersOptions, artifactType string, filters []referrerstore.Filter) (*referrerstore.ListReferrersResult, error) {
			return &referrerstore.ListReferrersResult{
				Referrers: []ocispecs.ReferenceDescriptor{
					{
						ArtifactType: "application/vnd.snyk-os.json",
						Digest:       "sha256:testdigest",
					},
				},
			}, nil
		},
		GetBlobContentFunc: func(ctx context.Context, subject common.Reference, digest common.Digest) ([]byte, error) {
			snykData := SnykOS{
				Vulnerabilities: []Vulnerability{
					{
						ID:        "vuln-1",
						CVSSScore: 3.5,
					},
				},
			}
			return json.Marshal(snykData)
		},
	}

	args := &skel.CmdArgs{
		StdinData: []byte(`{"config":{"maxCvssScore":5.0}}`),
	}
	subjectRef := common.Reference{Path: "test/path"}
	desc := ocispecs.ReferenceDescriptor{}

	result, err := VerifyReference(args, subjectRef, desc, mockStore)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsSuccess {
		t.Errorf("expected success, got failure: %v", result.Message)
	}
}

func TestVerifyReference_Failure(t *testing.T) {
	mockStore := &MockReferrerStore{
		ListReferrersFunc: func(ctx context.Context, subject common.Reference, opts *referrerstore.ListReferrersOptions, artifactType string, filters []referrerstore.Filter) (*referrerstore.ListReferrersResult, error) {
			return &referrerstore.ListReferrersResult{
				Referrers: []ocispecs.ReferenceDescriptor{
					{
						ArtifactType: "application/vnd.snyk-os.json",
						Digest:       "sha256:testdigest",
					},
				},
			}, nil
		},
		GetBlobContentFunc: func(ctx context.Context, subject common.Reference, digest common.Digest) ([]byte, error) {
			snykData := SnykOS{
				Vulnerabilities: []Vulnerability{
					{
						ID:        "vuln-1",
						CVSSScore: 7.0,
					},
				},
			}
			return json.Marshal(snykData)
		},
	}

	args := &skel.CmdArgs{
		StdinData: []byte(`{"config":{"maxCvssScore":5.0}}`),
	}
	subjectRef := common.Reference{Path: "test/path"}
	desc := ocispecs.ReferenceDescriptor{}

	result, err := VerifyReference(args, subjectRef, desc, mockStore)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.IsSuccess {
		t.Errorf("expected failure, got success")
	}

	expectedMsg := "Denied due to vulnerability vuln-1 with CVSS score 7.0"
	if result.Message != expectedMsg {
		t.Errorf("unexpected message: got %q, want %q", result.Message, expectedMsg)
	}
}

func TestLoadSnykOSData_Success(t *testing.T) {
	mockStore := &MockReferrerStore{
		ListReferrersFunc: func(ctx context.Context, subject common.Reference, opts *referrerstore.ListReferrersOptions, artifactType string, filters []referrerstore.Filter) (*referrerstore.ListReferrersResult, error) {
			return &referrerstore.ListReferrersResult{
				Referrers: []ocispecs.ReferenceDescriptor{
					{
						ArtifactType: "application/vnd.snyk-os.json",
						Digest:       "sha256:testdigest",
					},
				},
			}, nil
		},
		GetBlobContentFunc: func(ctx context.Context, subject common.Reference, digest common.Digest) ([]byte, error) {
			snykData := SnykOS{
				Vulnerabilities: []Vulnerability{
					{
						ID:        "vuln-1",
						CVSSScore: 4.0,
					},
				},
			}
			return json.Marshal(snykData)
		},
	}

	subjectRef := common.Reference{Path: "test/path"}

	data, err := loadSnykOSData(context.Background(), subjectRef, mockStore)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Vulnerabilities) != 1 {
		t.Errorf("unexpected number of vulnerabilities: got %d, want 1", len(data.Vulnerabilities))
	}
}

func TestLoadSnykOSData_NoArtifact(t *testing.T) {
	mockStore := &MockReferrerStore{
		ListReferrersFunc: func(ctx context.Context, subject common.Reference, opts *referrerstore.ListReferrersOptions, artifactType string, filters []referrerstore.Filter) (*referrerstore.ListReferrersResult, error) {
			return &referrerstore.ListReferrersResult{
				Referrers: []ocispecs.ReferenceDescriptor{},
			}, nil
		},
		GetBlobContentFunc: nil, // Shouldn't be called
	}

	subjectRef := common.Reference{Path: "test/path"}

	_, err := loadSnykOSData(context.Background(), subjectRef, mockStore)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	expectedErr := "snyk-os.json artifact not found"
	if err.Error() != expectedErr {
		t.Errorf("unexpected error message: got %q, want %q", err.Error(), expectedErr)
	}
}
