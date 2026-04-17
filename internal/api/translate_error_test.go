package api

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/smithy-go"
)

// apiErrorStub satisfies smithy.APIError correctly (unlike the shared
// mockAPIError in handlers_test.go, which returns int32 for ErrorFault and so
// fails the interface check in errors.As). Local to this file to avoid
// touching the shared mock and breaking other tests that depend on its
// current behaviour.
type apiErrorStub struct {
	code string
	msg  string
}

func (e *apiErrorStub) Error() string                 { return e.msg }
func (e *apiErrorStub) ErrorCode() string             { return e.code }
func (e *apiErrorStub) ErrorMessage() string          { return e.msg }
func (e *apiErrorStub) ErrorFault() smithy.ErrorFault { return smithy.FaultUnknown }

// Canary strings we deliberately embed in errors fed to TranslateError.
// If any of these appears in the S3Error.Message returned to clients, the
// leak-prevention contract has regressed.
const (
	canaryInternalURL   = "http://internal-backend.example.invalid:9000"
	canarySigHex        = "deadbeefcafef00dabad1deadeadbeefcafef00dabad1deadeadbeefcafef00d"
	canaryCredential    = "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	canaryInternalState = "internal invariant broken: do-not-leak"
)

// TestTranslateError_DefaultBranch_NoLeak exercises the default (unknown
// error) branch of TranslateError and asserts the returned Message does not
// contain any of the canary strings that were present in the wrapped error.
//
// This is the regression test for the vulnerability where the default branch
// did `fmt.Sprintf(..., "%v", err)` and forwarded arbitrary upstream error
// content into the response body.
func TestTranslateError_DefaultBranch_NoLeak(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{
			name: "bare error with internal url",
			err:  errors.New("dial tcp: connection refused to " + canaryInternalURL),
		},
		{
			name: "wrapped error chain with signature-shaped hex",
			err:  fmt.Errorf("s3 client failed: %w", errors.New("computed "+canarySigHex)),
		},
		{
			name: "error carrying credential-shaped substring",
			err:  errors.New("auth failed for " + canaryCredential),
		},
		{
			name: "error carrying internal invariant message",
			err:  errors.New(canaryInternalState),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := TranslateError(tc.err, "bucket", "key")
			if got == nil {
				t.Fatal("TranslateError returned nil for non-nil input")
			}
			if got.Code != "InternalError" {
				t.Errorf("Code = %q, want InternalError", got.Code)
			}
			for _, canary := range []string{canaryInternalURL, canarySigHex, canaryCredential, canaryInternalState} {
				if strings.Contains(got.Message, canary) {
					t.Errorf("Message leaked canary %q\nMessage: %s", canary, got.Message)
				}
			}
			// Defence-in-depth: the Message must not contain err.Error()
			// verbatim either.
			if strings.Contains(got.Message, tc.err.Error()) {
				t.Errorf("Message contains err.Error() verbatim\nerr: %s\nmsg: %s", tc.err.Error(), got.Message)
			}
		})
	}
}

// TestTranslateError_InvalidArgument_NoLeak asserts that the InvalidArgument
// branch no longer forwards apiErr.ErrorMessage() (which is backend-supplied
// and therefore potentially attacker-influenceable) into the response.
func TestTranslateError_InvalidArgument_NoLeak(t *testing.T) {
	apiErr := &apiErrorStub{
		code: "InvalidArgument",
		msg:  "backend-controlled message containing " + canaryInternalURL + " and " + canarySigHex,
	}

	got := TranslateError(apiErr, "bucket", "key")
	if got == nil {
		t.Fatal("TranslateError returned nil")
	}
	if got.Code != "InvalidArgument" {
		t.Errorf("Code = %q, want InvalidArgument", got.Code)
	}
	for _, canary := range []string{canaryInternalURL, canarySigHex} {
		if strings.Contains(got.Message, canary) {
			t.Errorf("Message leaked canary %q\nMessage: %s", canary, got.Message)
		}
	}
}

// TestTranslateError_KnownCodes_StillFixedMessages is a light sanity check
// that the known-code branches still produce the expected stable messages
// (they always did, but the refactor is adjacent so guard against collateral
// damage).
func TestTranslateError_KnownCodes_StillFixedMessages(t *testing.T) {
	cases := []struct {
		code       string
		wantPrefix string
		wantStatus int
	}{
		{"NoSuchBucket", "The specified bucket does not exist", 404},
		{"NoSuchKey", "The specified key does not exist", 404},
		{"NotFound", "The specified key does not exist", 404},
		{"AccessDenied", "Access Denied", 403},
		{"InvalidBucketName", "The specified bucket is not valid", 400},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			apiErr := &apiErrorStub{code: tc.code, msg: "backend says " + canaryInternalURL}
			got := TranslateError(apiErr, "bucket", "key")
			if got.HTTPStatus != tc.wantStatus {
				t.Errorf("HTTPStatus = %d, want %d", got.HTTPStatus, tc.wantStatus)
			}
			if !strings.HasPrefix(got.Message, tc.wantPrefix) {
				t.Errorf("Message = %q, want prefix %q", got.Message, tc.wantPrefix)
			}
			if strings.Contains(got.Message, canaryInternalURL) {
				t.Errorf("Message leaked canary\nMessage: %s", got.Message)
			}
		})
	}
}

// TestTranslateError_NilReturnsNil preserves the existing nil-safety contract.
func TestTranslateError_NilReturnsNil(t *testing.T) {
	if got := TranslateError(nil, "b", "k"); got != nil {
		t.Errorf("TranslateError(nil) = %+v, want nil", got)
	}
}
