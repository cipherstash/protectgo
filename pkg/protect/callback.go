package protect

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/cgo"
	"time"
)

// tokenCallbackTimeout bounds a single invocation of a token provider. It
// guards against a provider that hangs, since the native layer blocks on the
// callback return.
const tokenCallbackTimeout = 30 * time.Second

// tokenProvider holds a caller-supplied function that returns an authentication
// token. It is registered with a cgo.Handle and looked up by the exported
// callback when the native layer requests a token.
type tokenProvider struct {
	getToken func(ctx context.Context) (string, error)
}

// protectgoGetToken is the C-callable entry point invoked by the native layer
// when it needs a fresh token. The handle identifies the per-client
// tokenProvider registered in NewClient. The returned string is a NUL-terminated
// JSON envelope allocated on the C heap (via C.CString); the native layer frees
// it. A panic in the provider is recovered and reported as a failure envelope so
// it can never unwind across the FFI boundary into Rust.
//
//export protectgoGetToken
func protectgoGetToken(handle C.uint64_t) (result *C.char) {
	defer func() {
		if r := recover(); r != nil {
			result = C.CString(providerFailureEnvelope(fmt.Sprintf("panic in token callback: %v", r)))
		}
	}()

	return C.CString(tokenEnvelopeForHandle(uint64(handle)))
}

// tokenEnvelopeForHandle resolves the tokenProvider for handle, invokes it with
// a bounded context, and returns the JSON envelope to hand back to the native
// layer.
func tokenEnvelopeForHandle(handle uint64) string {
	provider, ok := cgo.Handle(handle).Value().(*tokenProvider)
	if !ok || provider == nil || provider.getToken == nil {
		return providerFailureEnvelope("invalid token callback handle")
	}

	ctx, cancel := context.WithTimeout(context.Background(), tokenCallbackTimeout)
	defer cancel()

	token, err := provider.getToken(ctx)
	return buildTokenEnvelope(token, err)
}

// buildTokenEnvelope builds the JSON envelope returned to the native layer.
// On success it is {"token":"<token>"}; on error it is a PROVIDER_ERROR failure
// envelope carrying the error message. It is a pure function so the envelope
// shape can be unit-tested without any cgo call.
func buildTokenEnvelope(token string, err error) string {
	if err != nil {
		return providerFailureEnvelope(err.Error())
	}
	b, marshalErr := json.Marshal(struct {
		Token string `json:"token"`
	}{Token: token})
	if marshalErr != nil {
		// A plain string token can always be marshaled; this is unreachable in
		// practice, but fail closed rather than return malformed JSON.
		return providerFailureEnvelope("failed to encode token envelope")
	}
	return string(b)
}

// providerFailureEnvelope builds a PROVIDER_ERROR failure envelope carrying msg.
func providerFailureEnvelope(msg string) string {
	type failureError struct {
		Message string `json:"message"`
	}
	type failure struct {
		Type  string       `json:"type"`
		Error failureError `json:"error"`
	}
	b, err := json.Marshal(struct {
		Failure failure `json:"failure"`
	}{
		Failure: failure{
			Type:  "PROVIDER_ERROR",
			Error: failureError{Message: msg},
		},
	})
	if err != nil {
		// Escaping msg failed (unreachable for valid UTF-8); return a minimal
		// valid envelope so the native layer still sees a failure.
		return `{"failure":{"type":"PROVIDER_ERROR","error":{"message":"token callback failed"}}}`
	}
	return string(b)
}
