package api

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/smithy-go"
)

// S3Error represents an S3 API error response.
type S3Error struct {
	Code       string
	Message    string
	Resource   string
	RequestID  string
	HTTPStatus int
}

// Error implements the error interface.
func (e *S3Error) Error() string {
	return fmt.Sprintf("S3 Error: %s - %s", e.Code, e.Message)
}

// WriteXML writes the S3 error response in XML format.
func (e *S3Error) WriteXML(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(e.HTTPStatus)

	// S3 Error Response structure
	type ErrorResponse struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string   `xml:"Code"`
		Message   string   `xml:"Message"`
		Resource  string   `xml:"Resource,omitempty"`
		RequestID string   `xml:"RequestId,omitempty"`
	}

	response := ErrorResponse{
		Code:      e.Code,
		Message:   e.Message,
		Resource:  e.Resource,
		RequestID: e.RequestID,
	}

	xmlData, err := xml.MarshalIndent(response, "", "  ")
	if err != nil {
		// Fallback to plain text if XML marshaling fails
		http.Error(w, e.Message, e.HTTPStatus)
		return
	}

	w.Write([]byte(xml.Header))
	w.Write(xmlData)
}

// TranslateError translates AWS SDK and other errors to S3 errors.
func TranslateError(err error, bucket, key string) *S3Error {
	if err == nil {
		return nil
	}

	// Extract request ID if available
	requestID := ""
	var opErr *smithy.OperationError
	if errors.As(err, &opErr) {
		if reqID := extractRequestID(opErr); reqID != "" {
			requestID = reqID
		}
	}

	resource := ""
	if bucket != "" {
		if key != "" {
			resource = fmt.Sprintf("/%s/%s", bucket, key)
		} else {
			resource = fmt.Sprintf("/%s", bucket)
		}
	}

	// Check for API errors first (smithy.APIError interface)
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchBucket":
			return &S3Error{
				Code:       "NoSuchBucket",
				Message:    fmt.Sprintf("The specified bucket does not exist: %s", bucket),
				Resource:   resource,
				RequestID:  requestID,
				HTTPStatus: http.StatusNotFound,
			}
		case "NoSuchKey", "NotFound":
			return &S3Error{
				Code:       "NoSuchKey",
				Message:    fmt.Sprintf("The specified key does not exist: %s", key),
				Resource:   resource,
				RequestID:  requestID,
				HTTPStatus: http.StatusNotFound,
			}
		case "AccessDenied":
			return &S3Error{
				Code:       "AccessDenied",
				Message:    "Access Denied",
				Resource:   resource,
				RequestID:  requestID,
				HTTPStatus: http.StatusForbidden,
			}
		case "InvalidBucketName":
			return &S3Error{
				Code:       "InvalidBucketName",
				Message:    "The specified bucket is not valid.",
				Resource:   resource,
				RequestID:  requestID,
				HTTPStatus: http.StatusBadRequest,
			}
		case "InvalidArgument":
			return &S3Error{
				Code:       "InvalidArgument",
				Message:    fmt.Sprintf("Invalid argument: %s", apiErr.ErrorMessage()),
				Resource:   resource,
				RequestID:  requestID,
				HTTPStatus: http.StatusBadRequest,
			}
		}
	}

	// Check for mock errors that contain error codes in the message
	errStr := err.Error()
	if strings.Contains(errStr, "does not exist") {
		return &S3Error{
			Code:       "NoSuchBucket",
			Message:    fmt.Sprintf("The specified bucket does not exist: %s", bucket),
			Resource:   resource,
			RequestID:  requestID,
			HTTPStatus: http.StatusNotFound,
		}
	}

	// Default to internal error
	return &S3Error{
		Code:       "InternalError",
		Message:    fmt.Sprintf("We encountered an internal error. Please try again: %v", err),
		Resource:   resource,
		RequestID:  requestID,
		HTTPStatus: http.StatusInternalServerError,
	}
}

// extractRequestID attempts to extract request ID from error.
func extractRequestID(err error) string {
	// Request ID extraction from AWS SDK errors would go here
	// For now, return empty string
	return ""
}

// Predefined S3 errors
var (
	ErrInvalidRequest = &S3Error{
		Code:       "InvalidRequest",
		Message:    "Invalid Request",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrInvalidBucketName = &S3Error{
		Code:       "InvalidBucketName",
		Message:    "The specified bucket is not valid.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrInvalidKeyName = &S3Error{
		Code:       "InvalidArgument",
		Message:    "The specified key is not valid.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrAccessDenied = &S3Error{
		Code:       "AccessDenied",
		Message:    "Access Denied",
		HTTPStatus: http.StatusForbidden,
	}

	ErrNoSuchBucket = &S3Error{
		Code:       "NoSuchBucket",
		Message:    "The specified bucket does not exist.",
		HTTPStatus: http.StatusNotFound,
	}

	ErrNoSuchKey = &S3Error{
		Code:       "NoSuchKey",
		Message:    "The specified key does not exist.",
		HTTPStatus: http.StatusNotFound,
	}

	ErrMethodNotAllowed = &S3Error{
		Code:       "MethodNotAllowed",
		Message:    "The specified method is not allowed against this resource.",
		HTTPStatus: http.StatusMethodNotAllowed,
	}
)
