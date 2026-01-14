package test

import (
	"testing"
)

// TestS3Gateway_Garage_EndToEnd tests basic PUT/GET operations against Garage backend.
func TestS3Gateway_Garage_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	garageServer := StartGarageServer(t)
	if garageServer == nil {
		t.Skip("Garage server not available")
	}
	defer garageServer.Stop()

	runEndToEndTest(t, garageServer.GetGatewayConfig(), garageServer.Bucket)
}

// TestS3Gateway_Garage_ChunkedUpload verify that chunked uploads work with Garage backend.
func TestS3Gateway_Garage_ChunkedUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	garageServer := StartGarageServer(t)
	if garageServer == nil {
		t.Skip("Garage server not available")
	}
	defer garageServer.Stop()

	runChunkedUploadTest(t, garageServer.GetGatewayConfig(), garageServer.Bucket)
}
