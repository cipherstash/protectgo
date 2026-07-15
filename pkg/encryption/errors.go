package encryption

import (
	"errors"
	"strings"
)

// Sentinel errors returned by the encryption SDK. Use errors.Is() to check
// for specific error conditions.
var (
	// ErrUnknownColumn indicates the column was not found in the encrypt config.
	ErrUnknownColumn = errors.New("encryption: unknown column")

	// ErrMissingIndex indicates the column does not have the required index type.
	ErrMissingIndex = errors.New("encryption: missing index")

	// ErrInvalidQueryInput indicates the query input value is invalid for the index type.
	ErrInvalidQueryInput = errors.New("encryption: invalid query input")

	// ErrInvalidJSONPath indicates an invalid JSON path was provided.
	ErrInvalidJSONPath = errors.New("encryption: invalid JSON path")

	// ErrUnknownQueryOp indicates an unknown query operation was requested.
	ErrUnknownQueryOp = errors.New("encryption: unknown query operation")

	// ErrClientClosed indicates the client has already been closed.
	ErrClientClosed = errors.New("encryption: client is closed")

	// ErrInvariantViolation indicates an internal invariant was violated.
	ErrInvariantViolation = errors.New("encryption: invariant violation")

	// ErrSteVecRequiresJSON indicates an ste_vec index requires a JSON cast type.
	ErrSteVecRequiresJSON = errors.New("encryption: ste_vec requires json cast type")

	// ErrUnsupportedFormat indicates the column's index configuration has no
	// equivalent in the selected encrypted format. This typically means a
	// column uses an index or cast type that the chosen ciphertext format
	// (see [WithEncryptedFormat]) cannot represent.
	ErrUnsupportedFormat = errors.New("encryption: unsupported encrypted format for column")

	// ErrInvalidCiphertext indicates a value passed for decryption is not a
	// valid ciphertext payload.
	ErrInvalidCiphertext = errors.New("encryption: invalid ciphertext")

	// ErrAuthStrategy indicates a client authentication strategy is
	// misconfigured — for example [WithOIDCFederation] was selected without a
	// workspace CRN, or a token callback is required but was not supplied.
	ErrAuthStrategy = errors.New("encryption: auth strategy misconfigured")

	// ErrFFI indicates an unclassified error from the FFI layer.
	// Use errors.Is(err, ErrFFI) to check if an error originated from the
	// underlying encryption engine when no more specific sentinel applies.
	ErrFFI = errors.New("encryption: FFI error")
)

// Error is a structured error from the encryption SDK.
// Use errors.Is() to check for specific sentinel errors.
type Error struct {
	// Op is the operation that failed (e.g., "Encrypt", "Decrypt").
	Op string

	// Err is the wrapped sentinel error for use with errors.Is().
	Err error

	// Message is the original error message from the FFI layer.
	Message string
}

// Error implements the error interface.
func (e *Error) Error() string { return e.Message }

// Unwrap returns the underlying sentinel error for use with errors.Is().
func (e *Error) Unwrap() error { return e.Err }

// newError creates a new Error with the sentinel inferred from the FFI message.
func newError(op, msg string) *Error {
	return &Error{
		Op:      op,
		Err:     inferSentinel(msg),
		Message: msg,
	}
}

// inferSentinel maps FFI error message patterns to sentinel errors.
func inferSentinel(msg string) error {
	switch {
	case strings.Contains(msg, "invariant violation"):
		return ErrInvariantViolation
	case strings.Contains(msg, "Unknown query operation"):
		return ErrUnknownQueryOp
	case strings.Contains(msg, "not found in Encrypt config"):
		return ErrUnknownColumn
	case strings.Contains(msg, "does not have a"):
		return ErrMissingIndex
	case strings.Contains(msg, "Invalid query input"):
		return ErrInvalidQueryInput
	case strings.Contains(msg, "Invalid JSON path"):
		return ErrInvalidJSONPath
	case strings.Contains(msg, "ste_vec index requires cast_as"):
		return ErrSteVecRequiresJSON
	case strings.Contains(msg, "no EQL v3 column type"):
		return ErrUnsupportedFormat
	case strings.Contains(msg, "invalid ciphertext"):
		return ErrInvalidCiphertext
	case strings.Contains(msg, "workspaceCrn is required"),
		strings.Contains(msg, "auth strategy requires a token callback"):
		return ErrAuthStrategy
	default:
		return ErrFFI
	}
}
