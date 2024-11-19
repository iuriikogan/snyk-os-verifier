package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ratify-project/ratify/pkg/common"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	"github.com/ratify-project/ratify/pkg/referrerstore"
	"github.com/ratify-project/ratify/pkg/verifier/plugin/skel"
)

type MockReferrerStore struct {
	ListReferrersFunc  func(ctx context.Context, subject common.Reference, opts *referrerstore.ListReferrersOptions) (*referrerstore.ListReferrersResult, error)
	GetBlobContentFunc func(ctx context.Context, subject common.Reference, digest string) ([]byte, error)
}

func (m *MockReferrerStore) ListReferrers(ctx context.Context, subject common.Reference, opts *referrerstore.ListReferrersOptions) (*referrerstore.ListReferrersResult, error) {
	return m.ListReferrersFunc(ctx, subject, opts)
}

func (m *MockReferrerStore) GetBlobContent(ctx context.Context, subject common.Reference, digest string) ([]byte, error) {
	return m.GetBlobContentFunc(ctx, subject, digest)
}

func TestVerifyReference_Success(t *testing.T) {
	mockStore := &MockReferrerStore{
		ListReferrersFunc: func(ctx context.Context, subject common.Reference, opts *referrerstore.ListReferrersOptions) (*referrerstore.ListReferrersResult, error) {
			return &referrerstore.ListReferrersResult{
				Referrers: []ocispecs.ReferenceDescriptor{
					{
						ArtifactType: "application/vnd.snyk-os.json",
						Digest:       "testdigest",
					},
				},
			}, nil
		},
		GetBlobContentFunc: func(ctx context.Context, subject common.Reference, digest string) ([]byte, error) {
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
		ListReferrersFunc: func(ctx context.Context, subject common.Reference, opts *referrerstore.ListReferrersOptions) (*referrerstore.ListReferrersResult, error) {
			return &referrerstore.ListReferrersResult{
				Referrers: []ocispecs.ReferenceDescriptor{
					{
						ArtifactType: "application/vnd.snyk-os.json",
						Digest:       "testdigest",
					},
				},
			}, nil
		},
		GetBlobContentFunc: func(ctx context.Context, subject common.Reference, digest string) ([]byte, error) {
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
		t.Errorf("unexpected message: got %q, want
