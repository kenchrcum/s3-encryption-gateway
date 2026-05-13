package api

import (
	"fmt"
	"net/http"
	"strings"
)

// ClientCredentials holds credentials extracted from a client request.
type ClientCredentials struct {
	AccessKey string
	SecretKey string
	// FromQueryParam is true when the secret key was extracted from the URL
	// query string (legacy Method 1). Callers should log a security warning
	// when this is true, as query-string credentials are visible to
	// intermediaries (proxies, CDNs, browser history, /proc/cmdline).
	FromQueryParam bool
}

// ExtractCredentials extracts AWS credentials from an HTTP request.
// It tries multiple methods in order:
// 1. Query parameters (AWSAccessKeyId, AWSSecretAccessKey) - explicit query auth (legacy/custom)
// 2. Query parameters (X-Amz-Credential) - Signature V4 presigned URL
// 3. Authorization header (Signature V4) - extracts access key, requires secret key lookup
// 4. Returns error if no credentials found
//
// Note: When extracting from Authorization header or X-Amz-Credential, only the access key is available.
// The secret key must be provided via a mapping or fallback mechanism.
func ExtractCredentials(r *http.Request) (*ClientCredentials, error) {
	// Method 1: Query parameters (explicit auth with secret)
	// SECURITY NOTE: Passing AWSSecretAccessKey via query parameters exposes
	// the secret to intermediaries (reverse proxies, CDNs, browser history,
	// server process listings). Prefer SigV4 Authorization header auth.
	accessKey := r.URL.Query().Get("AWSAccessKeyId")
	secretKey := r.URL.Query().Get("AWSSecretAccessKey")
	if accessKey != "" && secretKey != "" {
		return &ClientCredentials{
			AccessKey:      accessKey,
			SecretKey:      secretKey,
			FromQueryParam: true,
		}, nil
	}

	// Method 2: Presigned URL (Signature V4)
	// Format: X-Amz-Credential=ACCESS_KEY/YYYYMMDD/REGION/SERVICE/aws4_request
	if credential := r.URL.Query().Get("X-Amz-Credential"); credential != "" {
		parts := strings.Split(credential, "/")
		if len(parts) > 0 && parts[0] != "" {
			return &ClientCredentials{
				AccessKey: parts[0],
				SecretKey: "", // Must be resolved by caller
			}, nil
		}
	}

	// Method 3: Authorization header (Signature V4)
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
	// Check explicit query parameters
	if r.URL.Query().Get("AWSAccessKeyId") != "" && r.URL.Query().Get("AWSSecretAccessKey") != "" {
		return true
	}
	// Check Presigned URL V4
	if r.URL.Query().Get("X-Amz-Credential") != "" {
		return true
	}
	// Check Authorization header
	if r.Header.Get("Authorization") != "" {
		return true
	}
	return false
}

// IsSignatureV4Request reports whether the request carries a SigV4
// Authorization header ("AWS4-HMAC-SHA256 ...") or SigV4 query parameters
// (X-Amz-Algorithm=AWS4-HMAC-SHA256).
func IsSignatureV4Request(r *http.Request) bool {
	if r.URL.Query().Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256" {
		return true
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}
	return strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256")
}

// IsSignatureV2Request reports whether the request carries a SigV2
// Authorization header ("AWS ACCESS_KEY:SIG") or V2 query parameters
// (AWSAccessKeyId + Signature).
func IsSignatureV2Request(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "AWS ") {
		return true
	}
	q := r.URL.Query()
	return q.Get("AWSAccessKeyId") != "" && q.Get("Signature") != ""
}
