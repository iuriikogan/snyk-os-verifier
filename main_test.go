package main

import (
	"context"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/ratify-project/ratify/pkg/common"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	"github.com/ratify-project/ratify/pkg/referrerstore"
	"github.com/ratify-project/ratify/pkg/referrerstore/config"
	"github.com/ratify-project/ratify/pkg/verifier/plugin/skel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockReferrerStore is a mock implementation of the ReferrerStore interface
type MockReferrerStore struct {
	mock.Mock
}

// Name mocks the Name method of ReferrerStore
func (m *MockReferrerStore) Name() string {
	args := m.Called()
	return args.String(0)
}

// ListReferrers mocks the ListReferrers method of ReferrerStore
func (m *MockReferrerStore) ListReferrers(ctx context.Context, subjectReference common.Reference, artifactTypes []string, nextToken string, subjectDesc *ocispecs.SubjectDescriptor) (referrerstore.ListReferrersResult, error) {
	args := m.Called(ctx, subjectReference, artifactTypes, nextToken, subjectDesc)
	return args.Get(0).(referrerstore.ListReferrersResult), args.Error(1)
}

// GetBlobContent mocks the GetBlobContent method of ReferrerStore
func (m *MockReferrerStore) GetBlobContent(ctx context.Context, subjectReference common.Reference, digest digest.Digest) ([]byte, error) {
	args := m.Called(ctx, subjectReference, digest)
	return args.Get(0).([]byte), args.Error(1)
}

// GetReferenceManifest mocks the GetReferenceManifest method of ReferrerStore
func (m *MockReferrerStore) GetReferenceManifest(ctx context.Context, subjectReference common.Reference, referenceDesc ocispecs.ReferenceDescriptor) (ocispecs.ReferenceManifest, error) {
	args := m.Called(ctx, subjectReference, referenceDesc)
	return args.Get(0).(ocispecs.ReferenceManifest), args.Error(1)
}

// GetConfig mocks the GetConfig method of ReferrerStore
func (m *MockReferrerStore) GetConfig() *config.StoreConfig {
	args := m.Called()
	return args.Get(0).(*config.StoreConfig)
}

// GetSubjectDescriptor mocks the GetSubjectDescriptor method of ReferrerStore
func (m *MockReferrerStore) GetSubjectDescriptor(ctx context.Context, subjectReference common.Reference) (*ocispecs.SubjectDescriptor, error) {
	args := m.Called(ctx, subjectReference)
	return args.Get(0).(*ocispecs.SubjectDescriptor), args.Error(1)
}

// mockReferrerStore returns a MockReferrerStore with pre-configured mock data
func mockReferrerStore() *MockReferrerStore {
	mockStore := new(MockReferrerStore)

	// Mock ListReferrers to return a reference descriptor for snyk-os.json type
	mockStore.On("ListReferrers", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(referrerstore.ListReferrersResult{
			Referrers: []ocispecs.ReferenceDescriptor{
				{
					ArtifactType: "application/vnd.snyk-os.json",
					Digest:       digest.FromString("testdigest1"),
				},
			},
		}, nil)

	// Mock GetBlobContent to return example snyk-os.json content
	mockStore.On("GetBlobContent", mock.Anything, mock.Anything, digest.FromString("testdigest1")).
		Return([]byte(`{"vulnerabilities":[{"id":"SNYK-JS-BL-608877","title":"Remote Memory Exposure","severity":"high","cvssScore":7.6}]}`), nil)

	return mockStore
}

func TestVerifyReference(t *testing.T) {
	// Create a mock referrer store
	mockStore := mockReferrerStore()

	// Set up the test args
	args := &skel.CmdArgs{
		StdinData: []byte(`{"config":{"maxCvssScore":7.5}}`), // Mock input for max CVSS score
	}

	// Mock subjectReference and referenceDescriptor
	subjectReference := common.Reference{
		// Add mock data for subjectReference here, if necessary
	}
	referenceDescriptor := ocispecs.ReferenceDescriptor{
		ArtifactType: "application/vnd.snyk-os.json",
		Digest:       digest.FromString("testdigest1"), // Ensure this matches mock data
	}

	// Call VerifyReference with mock data
	result, err := VerifyReference(args, subjectReference, referenceDescriptor, mockStore)

	// Assertions
	assert.NoError(t, err)
	assert.False(t, result.IsSuccess)
	assert.Contains(t, result.Message, "Denied due to vulnerability")
}
