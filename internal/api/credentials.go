package api

import (
	"fmt"
	"net/http"
	"strings"
)

// ClientCredentials holds credentials extracted from a client request.
type ClientCredentials struct {
	AccessKey string
	SecretKey  string
}

// ExtractCredentials extracts AWS credentials from an HTTP request.
// It tries multiple methods in order:
// 1. Query parameters (AWSAccessKeyId, AWSSecretAccessKey) - common for presigned URLs
// 2. Authorization header (Signature V4) - extracts access key, requires secret key lookup
// 3. Returns error if no credentials found
//
// Note: When extracting from Authorization header, only the access key is available.
// The secret key must be provided via a mapping or fallback mechanism.
func ExtractCredentials(r *http.Request) (*ClientCredentials, error) {
	// Method 1: Query parameters (for presigned URLs or simple auth)
	accessKey := r.URL.Query().Get("AWSAccessKeyId")
	secretKey := r.URL.Query().Get("AWSSecretAccessKey")
	if accessKey != "" && secretKey != "" {
		return &ClientCredentials{
			AccessKey: accessKey,
			SecretKey: secretKey,
		}, nil
	}

	// Method 2: Authorization header (Signature V4)
	// Format: AWS4-HMAC-SHA256 Credential=ACCESS_KEY/YYYYMMDD/REGION/s3/aws4_request, ...
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Try to extract access key from Credential part
		// Example: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, ..."
		if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") || strings.HasPrefix(authHeader, "AWS ") {
			// For AWS Signature V4, extract the access key
			credentialStart := strings.Index(authHeader, "Credential=")
			if credentialStart != -1 {
				credentialPart := authHeader[credentialStart+11:] // Skip "Credential="
				// Find the comma or space after the credential
				endIdx := strings.IndexAny(credentialPart, ", ")
				if endIdx == -1 {
					endIdx = len(credentialPart)
				}
				credential := credentialPart[:endIdx]
				
				// Parse: ACCESS_KEY/YYYYMMDD/REGION/s3/aws4_request
				parts := strings.Split(credential, "/")
				if len(parts) > 0 && parts[0] != "" {
					accessKey = parts[0]
					// For Signature V4, we only get the access key, not the secret
					// The secret key is used to sign the request, but we need it to make requests
					// Return partial credentials (caller must provide secret key mapping)
					if accessKey != "" {
						return &ClientCredentials{
							AccessKey: accessKey,
							SecretKey: "", // Must be resolved by caller
						}, nil
					}
				}
			} else {
				// Try legacy AWS signature format: "AWS ACCESS_KEY:SIGNATURE"
				// This is Signature Version 1, less common but still used
				parts := strings.Fields(authHeader)
				if len(parts) >= 2 && strings.HasPrefix(parts[0], "AWS") {
					credParts := strings.Split(parts[1], ":")
					if len(credParts) > 0 {
						accessKey = credParts[0]
						if accessKey != "" {
							return &ClientCredentials{
								AccessKey: accessKey,
								SecretKey: "", // Must be resolved by caller
							}, nil
						}
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("no credentials found in request")
}

// HasCredentials checks if the request contains credentials.
func HasCredentials(r *http.Request) bool {
	// Check query parameters
	if r.URL.Query().Get("AWSAccessKeyId") != "" && r.URL.Query().Get("AWSSecretAccessKey") != "" {
		return true
	}
	// Check Authorization header
	if r.Header.Get("Authorization") != "" {
		return true
	}
	return false
}

// IsSignatureV4Request checks if the request uses AWS Signature V4 authentication.
// Signature V4 requests include an Authorization header but the secret key is not
// transmitted (it's used to sign the request).
func IsSignatureV4Request(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}
	// Check if it's Signature V4 format
	if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
		return true
	}
	// Check for legacy AWS signature
	if strings.HasPrefix(authHeader, "AWS ") {
		return true
	}
	return false
}

