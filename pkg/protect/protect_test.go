package protect

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// Identifier tests
// ---------------------------------------------------------------------------

func TestIdentifier(t *testing.T) {
	t.Parallel()

	ident := Identifier{Table: "users", Column: "email"}

	if ident.Table != "users" {
		t.Errorf("Expected table 'users', got %q", ident.Table)
	}
	if ident.Column != "email" {
		t.Errorf("Expected column 'email', got %q", ident.Column)
	}
}

func TestIdentifierJSON(t *testing.T) {
	t.Parallel()

	ident := Identifier{Table: "users", Column: "email"}

	data, err := json.Marshal(ident)
	if err != nil {
		t.Fatalf("Failed to marshal Identifier: %v", err)
	}

	var decoded Identifier
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal Identifier: %v", err)
	}

	if decoded.Table != "users" || decoded.Column != "email" {
		t.Errorf("Round-trip failed: got table=%q column=%q", decoded.Table, decoded.Column)
	}
}

// ---------------------------------------------------------------------------
// CastAs tests
// ---------------------------------------------------------------------------

func TestCastAsConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		constant CastAs
		expected string
	}{
		{"Text", CastAsText, "text"},
		{"BigInt", CastAsBigInt, "bigint"},
		{"Int", CastAsInt, "int"},
		{"SmallInt", CastAsSmallInt, "small_int"},
		{"Float", CastAsFloat, "float"},
		{"Decimal", CastAsDecimal, "decimal"},
		{"Boolean", CastAsBoolean, "boolean"},
		{"Date", CastAsDate, "date"},
		{"Timestamp", CastAsTimestamp, "timestamp"},
		{"JSON", CastAsJSON, "json"},
		{"String (legacy alias)", CastAsString, "string"},
		{"Number (legacy alias)", CastAsNumber, "number"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if string(tc.constant) != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, string(tc.constant))
			}
		})
	}
}

func TestNormalizeCastAs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input CastAs
		want  CastAs
	}{
		{"string alias to text", CastAsString, CastAsText},
		{"number alias to float", CastAsNumber, CastAsFloat},
		{"bigint to big_int", CastAsBigInt, "big_int"},
		{"text unchanged", CastAsText, CastAsText},
		{"int unchanged", CastAsInt, CastAsInt},
		{"small_int unchanged", CastAsSmallInt, CastAsSmallInt},
		{"float unchanged", CastAsFloat, CastAsFloat},
		{"decimal unchanged", CastAsDecimal, CastAsDecimal},
		{"boolean unchanged", CastAsBoolean, CastAsBoolean},
		{"date unchanged", CastAsDate, CastAsDate},
		{"timestamp unchanged", CastAsTimestamp, CastAsTimestamp},
		{"json unchanged", CastAsJSON, CastAsJSON},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeCastAs(tc.input); got != tc.want {
				t.Errorf("normalizeCastAs(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// QueryType tests
// ---------------------------------------------------------------------------

func TestQueryTypeConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		constant QueryType
		expected string
	}{
		{"Equality", Equality, "unique"},
		{"FreeTextSearch", FreeTextSearch, "match"},
		{"OrderAndRange", OrderAndRange, "ore"},
		{"JSONSelector", JSONSelector, "ste_vec_selector"},
		{"JSONContains", JSONContains, "ste_vec_term"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if string(tc.constant) != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, string(tc.constant))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// resolveQueryType tests
// ---------------------------------------------------------------------------

func TestResolveQueryType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		queryType     QueryType
		wantIndexType string
		wantQueryOp   string
	}{
		{"Equality", Equality, "unique", "default"},
		{"FreeTextSearch", FreeTextSearch, "match", "default"},
		{"OrderAndRange", OrderAndRange, "ore", "default"},
		{"JSONSelector", JSONSelector, "ste_vec", "ste_vec_selector"},
		{"JSONContains", JSONContains, "ste_vec", "ste_vec_term"},
		{"Unknown", QueryType("custom"), "custom", "default"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			indexType, queryOp := resolveQueryType(tc.queryType)
			if indexType != tc.wantIndexType {
				t.Errorf("indexType: got %q, want %q", indexType, tc.wantIndexType)
			}
			if queryOp != tc.wantQueryOp {
				t.Errorf("queryOp: got %q, want %q", queryOp, tc.wantQueryOp)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ColumnRef tests
// ---------------------------------------------------------------------------

func TestColumnRefFromTableDef(t *testing.T) {
	t.Parallel()

	td := &TableDef{
		name: "users",
		columns: map[string]Column{
			"email": {CastAs: castPtr(CastAsString)},
			"age":   {CastAs: castPtr(CastAsNumber)},
		},
	}

	col := td.Column("email")
	if col.table != "users" {
		t.Errorf("table: got %q, want %q", col.table, "users")
	}
	if col.column != "email" {
		t.Errorf("column: got %q, want %q", col.column, "email")
	}
}

func TestColumnRefPanicsOnUnknownColumn(t *testing.T) {
	t.Parallel()

	td := &TableDef{
		name: "users",
		columns: map[string]Column{
			"email": {CastAs: castPtr(CastAsString)},
		},
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for unknown column")
		}
	}()
	td.Column("nonexistent")
}

// ---------------------------------------------------------------------------
// ClientOption tests
// ---------------------------------------------------------------------------

func TestWithSchemas(t *testing.T) {
	t.Parallel()

	td1 := &TableDef{name: "users", columns: map[string]Column{}}
	td2 := &TableDef{name: "orders", columns: map[string]Column{}}

	cfg := &clientConfig{}
	WithSchemas(td1, td2)(cfg)

	if len(cfg.schemas) != 2 {
		t.Fatalf("schemas count: got %d, want 2", len(cfg.schemas))
	}
	if cfg.schemas[0].name != "users" {
		t.Errorf("schema[0]: got %q, want %q", cfg.schemas[0].name, "users")
	}
	if cfg.schemas[1].name != "orders" {
		t.Errorf("schema[1]: got %q, want %q", cfg.schemas[1].name, "orders")
	}
}

func TestWithCredentials(t *testing.T) {
	t.Parallel()

	cfg := &clientConfig{}
	WithCredentials("crn", "key", "id", "secret")(cfg)

	if cfg.workspaceCRN != "crn" {
		t.Errorf("workspaceCRN: got %q, want %q", cfg.workspaceCRN, "crn")
	}
	if cfg.accessKey != "key" {
		t.Errorf("accessKey: got %q, want %q", cfg.accessKey, "key")
	}
	if cfg.clientID != "id" {
		t.Errorf("clientID: got %q, want %q", cfg.clientID, "id")
	}
	if cfg.clientKey != "secret" {
		t.Errorf("clientKey: got %q, want %q", cfg.clientKey, "secret")
	}
}

func TestWithKeyset(t *testing.T) {
	t.Parallel()

	cfg := &clientConfig{}
	WithKeyset("tenant-a")(cfg)

	if cfg.keysetName != "tenant-a" {
		t.Errorf("keysetName: got %q, want %q", cfg.keysetName, "tenant-a")
	}
}

func TestWithKeysetID(t *testing.T) {
	t.Parallel()

	cfg := &clientConfig{}
	WithKeysetID("ks-123")(cfg)

	if cfg.keysetID != "ks-123" {
		t.Errorf("keysetID: got %q, want %q", cfg.keysetID, "ks-123")
	}
}

// ---------------------------------------------------------------------------
// Operation Option tests
// ---------------------------------------------------------------------------

func TestWithLockContext(t *testing.T) {
	t.Parallel()

	lc := &LockContext{IdentityClaim: []string{"user:123"}}
	co := buildCallOpts([]Option{WithLockContext(lc)})

	if co.lockContext == nil {
		t.Fatal("lockContext: expected non-nil")
	}
	if len(co.lockContext.IdentityClaim) != 1 || co.lockContext.IdentityClaim[0] != "user:123" {
		t.Errorf("lockContext.IdentityClaim: got %v, want [user:123]", co.lockContext.IdentityClaim)
	}
}

func TestWithAuditContext(t *testing.T) {
	t.Parallel()

	audit := map[string]string{"action": "test"}
	co := buildCallOpts([]Option{WithAuditContext(audit)})

	if co.unverifiedContext == nil {
		t.Fatal("unverifiedContext: expected non-nil")
	}
	m, ok := co.unverifiedContext.(map[string]string)
	if !ok {
		t.Fatalf("unverifiedContext: expected map[string]string, got %T", co.unverifiedContext)
	}
	if m["action"] != "test" {
		t.Errorf("unverifiedContext[action]: got %q, want %q", m["action"], "test")
	}
}

func TestBuildCallOptsEmpty(t *testing.T) {
	t.Parallel()

	co := buildCallOpts(nil)

	if co.lockContext != nil {
		t.Error("lockContext: expected nil")
	}
	if co.unverifiedContext != nil {
		t.Error("unverifiedContext: expected nil")
	}
}

// ---------------------------------------------------------------------------
// Auth strategy and format option tests
// ---------------------------------------------------------------------------

func TestWithOIDCFederation(t *testing.T) {
	t.Parallel()

	getToken := func(context.Context) (string, error) { return "jwt", nil }
	cfg := &clientConfig{}
	WithOIDCFederation(getToken)(cfg)

	if cfg.oidcGetToken == nil {
		t.Fatal("oidcGetToken: expected non-nil")
	}
	if cfg.tokenProviderGetToken != nil {
		t.Error("tokenProviderGetToken: expected nil")
	}
	tok, err := cfg.oidcGetToken(context.Background())
	if err != nil || tok != "jwt" {
		t.Errorf("oidcGetToken() = (%q, %v), want (\"jwt\", nil)", tok, err)
	}
}

func TestWithTokenProvider(t *testing.T) {
	t.Parallel()

	getToken := func(context.Context) (string, error) { return "cts-token", nil }
	cfg := &clientConfig{}
	WithTokenProvider(getToken)(cfg)

	if cfg.tokenProviderGetToken == nil {
		t.Fatal("tokenProviderGetToken: expected non-nil")
	}
	if cfg.oidcGetToken != nil {
		t.Error("oidcGetToken: expected nil")
	}
}

func TestWithEncryptedFormat(t *testing.T) {
	t.Parallel()

	cfg := &clientConfig{}
	WithEncryptedFormat(EncryptedFormatV3)(cfg)
	if cfg.encryptedFormat != EncryptedFormatV3 {
		t.Errorf("encryptedFormat: got %d, want %d", cfg.encryptedFormat, EncryptedFormatV3)
	}
}

func TestResolveEqlVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input EncryptedFormat
		want  int
	}{
		{"unset defaults to v2", EncryptedFormat(0), 2},
		{"explicit v2", EncryptedFormatV2, 2},
		{"explicit v3", EncryptedFormatV3, 3},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := resolveEqlVersion(tc.input); got != tc.want {
				t.Errorf("resolveEqlVersion(%d) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// NewClient must reject WithOIDCFederation without a workspace CRN before it
// makes any FFI call.
func TestNewClientOIDCWithoutCRN(t *testing.T) {
	// Not parallel: mutates the CS_WORKSPACE_CRN environment variable.
	t.Setenv("CS_WORKSPACE_CRN", "")

	_, err := NewClient(context.Background(),
		WithOIDCFederation(func(context.Context) (string, error) { return "jwt", nil }),
	)
	if err == nil {
		t.Fatal("expected error for OIDC federation without a workspace CRN")
	}
	if !errors.Is(err, ErrAuthStrategy) {
		t.Errorf("expected ErrAuthStrategy, got: %v", err)
	}
}

// NewClient must reject configuring both auth strategies at once before any FFI
// call.
func TestNewClientMutuallyExclusiveAuthStrategies(t *testing.T) {
	t.Parallel()

	_, err := NewClient(context.Background(),
		WithOIDCFederation(func(context.Context) (string, error) { return "jwt", nil }),
		WithTokenProvider(func(context.Context) (string, error) { return "cts", nil }),
	)
	if err == nil {
		t.Fatal("expected error for mutually exclusive auth strategies")
	}
	if !errors.Is(err, ErrAuthStrategy) {
		t.Errorf("expected ErrAuthStrategy, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// EncryptConfig building tests
// ---------------------------------------------------------------------------

func TestBuildEncryptConfigFromSchemas(t *testing.T) {
	t.Parallel()

	td := &TableDef{
		name: "users",
		columns: map[string]Column{
			"email": {CastAs: castPtr(CastAsString)},
			"age":   {CastAs: castPtr(CastAsNumber)},
		},
	}

	config := buildEncryptConfigFromSchemas([]*TableDef{td})

	if config.Version != 1 {
		t.Errorf("version: got %d, want 1", config.Version)
	}
	if len(config.Tables) != 1 {
		t.Fatalf("tables: got %d, want 1", len(config.Tables))
	}
	usersTable, ok := config.Tables["users"]
	if !ok {
		t.Fatal("missing users table")
	}
	if len(usersTable) != 2 {
		t.Errorf("user columns: got %d, want 2", len(usersTable))
	}
}

func TestBuildEncryptConfigFromSchemasMultiple(t *testing.T) {
	t.Parallel()

	td1 := &TableDef{name: "users", columns: map[string]Column{"email": {}}}
	td2 := &TableDef{name: "orders", columns: map[string]Column{"total": {}}}

	config := buildEncryptConfigFromSchemas([]*TableDef{td1, td2})

	if len(config.Tables) != 2 {
		t.Fatalf("tables: got %d, want 2", len(config.Tables))
	}
	if _, ok := config.Tables["users"]; !ok {
		t.Error("missing users table")
	}
	if _, ok := config.Tables["orders"]; !ok {
		t.Error("missing orders table")
	}
}

// ---------------------------------------------------------------------------
// Encrypted struct tests
// ---------------------------------------------------------------------------

func TestEncryptedStruct(t *testing.T) {
	t.Parallel()

	ct := "ciphertext-value"
	ore := []string{"ore1", "ore2"}
	match := []uint16{1, 2, 3}
	unique := "unique-hash"

	encrypted := Encrypted{
		Identifier:  Identifier{Table: "users", Column: "email"},
		Version:     1,
		Ciphertext:  &ct,
		OreIndex:    &ore,
		MatchIndex:  &match,
		UniqueIndex: &unique,
	}

	if encrypted.Identifier.Table != "users" {
		t.Errorf("Expected table 'users', got %q", encrypted.Identifier.Table)
	}
	if encrypted.Version != 1 {
		t.Errorf("Expected version 1, got %d", encrypted.Version)
	}
	if *encrypted.Ciphertext != "ciphertext-value" {
		t.Errorf("Expected 'ciphertext-value', got %q", *encrypted.Ciphertext)
	}
}

func TestEncryptedJSON(t *testing.T) {
	t.Parallel()

	ct := "ciphertext-value"
	encrypted := Encrypted{
		Identifier: Identifier{Table: "users", Column: "email"},
		Version:    1,
		Ciphertext: &ct,
	}

	data, err := json.Marshal(encrypted)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded["c"] != "ciphertext-value" {
		t.Errorf("Expected c='ciphertext-value', got %v", decoded["c"])
	}
	if decoded["v"] == nil {
		t.Error("Expected 'v' field to be present")
	}
}

func TestEncryptedJSONRoundTrip(t *testing.T) {
	t.Parallel()

	ct := "cipher"
	ore := []string{"a", "b"}
	unique := "hmac"

	original := Encrypted{
		Identifier:  Identifier{Table: "t", Column: "c"},
		Version:     1,
		Ciphertext:  &ct,
		OreIndex:    &ore,
		UniqueIndex: &unique,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Encrypted
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Identifier.Table != "t" || decoded.Identifier.Column != "c" {
		t.Errorf("identifier: got t=%q c=%q", decoded.Identifier.Table, decoded.Identifier.Column)
	}
	if *decoded.Ciphertext != "cipher" {
		t.Errorf("ciphertext: got %q, want %q", *decoded.Ciphertext, "cipher")
	}
	if decoded.UniqueIndex == nil || *decoded.UniqueIndex != "hmac" {
		t.Errorf("uniqueIndex: got %v, want %q", decoded.UniqueIndex, "hmac")
	}
}

func TestEncryptedKindAndOpRoundTrip(t *testing.T) {
	t.Parallel()

	k := "ct"
	op := "eq"
	ct := "cipher"
	original := Encrypted{
		Identifier: Identifier{Table: "t", Column: "c"},
		Version:    2,
		K:          &k,
		Ciphertext: &ct,
		Op:         &op,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// The k and op fields must appear in the wire JSON.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}
	if raw["k"] != "ct" {
		t.Errorf("k: got %v, want %q", raw["k"], "ct")
	}
	if raw["op"] != "eq" {
		t.Errorf("op: got %v, want %q", raw["op"], "eq")
	}

	var decoded Encrypted
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if decoded.K == nil || *decoded.K != "ct" {
		t.Errorf("K: got %v, want %q", decoded.K, "ct")
	}
	if decoded.Op == nil || *decoded.Op != "eq" {
		t.Errorf("Op: got %v, want %q", decoded.Op, "eq")
	}
}

func TestEncryptedOmitsKindAndOpWhenNil(t *testing.T) {
	t.Parallel()

	ct := "cipher"
	enc := Encrypted{
		Identifier: Identifier{Table: "t", Column: "c"},
		Version:    2,
		Ciphertext: &ct,
	}
	data, err := json.Marshal(enc)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if _, ok := raw["k"]; ok {
		t.Error("k: should be omitted when nil")
	}
	if _, ok := raw["op"]; ok {
		t.Error("op: should be omitted when nil")
	}
}

// ---------------------------------------------------------------------------
// QueryTerm tests
// ---------------------------------------------------------------------------

func TestQueryTermObject(t *testing.T) {
	t.Parallel()

	var qt QueryTerm
	if err := json.Unmarshal([]byte(`{"hm":"abc","i":{"t":"users","c":"email"}}`), &qt); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if got := qt.String(); got != `{"hm":"abc","i":{"t":"users","c":"email"}}` {
		t.Errorf("String(): got %q", got)
	}

	// Marshaling must reproduce the raw JSON verbatim.
	out, err := json.Marshal(qt)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	if string(out) != `{"hm":"abc","i":{"t":"users","c":"email"}}` {
		t.Errorf("MarshalJSON: got %s", out)
	}
}

func TestQueryTermBareString(t *testing.T) {
	t.Parallel()

	// A query term may be a bare JSON string, e.g. an ste_vec selector.
	var qt QueryTerm
	if err := json.Unmarshal([]byte(`"c2VsZWN0b3I="`), &qt); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if got := qt.String(); got != `"c2VsZWN0b3I="` {
		t.Errorf("String(): got %q", got)
	}
	if got := string(qt.Bytes()); got != `"c2VsZWN0b3I="` {
		t.Errorf("Bytes(): got %q", got)
	}
}

func TestQueryTermZeroValueMarshalsNull(t *testing.T) {
	t.Parallel()

	var qt QueryTerm
	out, err := json.Marshal(qt)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	if string(out) != "null" {
		t.Errorf("MarshalJSON: got %s, want null", out)
	}
}

func TestQueryTermInStruct(t *testing.T) {
	t.Parallel()

	// A QueryTerm embedded in a larger payload round-trips its raw value.
	type payload struct {
		Term *QueryTerm `json:"term"`
	}
	var p payload
	if err := json.Unmarshal([]byte(`{"term":{"ob":["x"]}}`), &p); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if p.Term == nil {
		t.Fatal("Term: expected non-nil")
	}
	out, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if string(out) != `{"term":{"ob":["x"]}}` {
		t.Errorf("round-trip: got %s", out)
	}
}

// ---------------------------------------------------------------------------
// Token callback envelope tests
// ---------------------------------------------------------------------------

func TestBuildTokenEnvelopeSuccess(t *testing.T) {
	t.Parallel()

	got := buildTokenEnvelope("my-token", nil)
	if got != `{"token":"my-token"}` {
		t.Errorf("buildTokenEnvelope: got %s", got)
	}
}

func TestBuildTokenEnvelopeFailure(t *testing.T) {
	t.Parallel()

	got := buildTokenEnvelope("", errors.New("network down"))

	var env struct {
		Failure struct {
			Type  string `json:"type"`
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		} `json:"failure"`
	}
	if err := json.Unmarshal([]byte(got), &env); err != nil {
		t.Fatalf("failure envelope is not valid JSON: %v (%s)", err, got)
	}
	if env.Failure.Type != "PROVIDER_ERROR" {
		t.Errorf("failure type: got %q, want %q", env.Failure.Type, "PROVIDER_ERROR")
	}
	if env.Failure.Error.Message != "network down" {
		t.Errorf("failure message: got %q, want %q", env.Failure.Error.Message, "network down")
	}
}

func TestProviderFailureEnvelopeEscapesMessage(t *testing.T) {
	t.Parallel()

	// A message containing quotes must still yield valid JSON.
	got := providerFailureEnvelope(`he said "boom"`)
	var env map[string]any
	if err := json.Unmarshal([]byte(got), &env); err != nil {
		t.Fatalf("envelope is not valid JSON: %v (%s)", err, got)
	}
}

// ---------------------------------------------------------------------------
// DecryptResult tests
// ---------------------------------------------------------------------------

func TestDecryptResult(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		r := DecryptResult{Data: "hello"}
		if r.Data != "hello" {
			t.Errorf("Data: got %v, want %q", r.Data, "hello")
		}
		if r.Err != nil {
			t.Errorf("Err: got %v, want nil", r.Err)
		}
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()
		r := DecryptResult{Err: errors.New("failed")}
		if r.Data != nil {
			t.Errorf("Data: got %v, want nil", r.Data)
		}
		if r.Err == nil || r.Err.Error() != "failed" {
			t.Errorf("Err: got %v, want 'failed'", r.Err)
		}
	})

	t.Run("numeric data", func(t *testing.T) {
		t.Parallel()
		r := DecryptResult{Data: 42.0}
		if r.Data != 42.0 {
			t.Errorf("Data: got %v, want 42.0", r.Data)
		}
	})

	t.Run("nil data", func(t *testing.T) {
		t.Parallel()
		r := DecryptResult{}
		if r.Data != nil {
			t.Errorf("Data: got %v, want nil", r.Data)
		}
	})
}

// ---------------------------------------------------------------------------
// Error and sentinel tests
// ---------------------------------------------------------------------------

func TestErrorSentinels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		message  string
		sentinel error
	}{
		{
			"invariant violation",
			"invariant violation: something went wrong",
			ErrInvariantViolation,
		},
		{
			"unknown query op",
			"Unknown query operation 'foo'",
			ErrUnknownQueryOp,
		},
		{
			"unknown column",
			"column 'bar' not found in Encrypt config",
			ErrUnknownColumn,
		},
		{
			"missing index",
			"column 'baz' does not have a match index",
			ErrMissingIndex,
		},
		{
			"invalid query input",
			"Invalid query input: expected string",
			ErrInvalidQueryInput,
		},
		{
			"invalid json path",
			"Invalid JSON path: $.foo.bar",
			ErrInvalidJSONPath,
		},
		{
			"ste_vec requires json",
			"ste_vec index requires cast_as to be json",
			ErrSteVecRequiresJSON,
		},
		{
			"unsupported format for column",
			"column \"email\": no EQL v3 column type for this configuration",
			ErrUnsupportedFormat,
		},
		{
			"invalid ciphertext",
			"invalid ciphertext: could not parse payload",
			ErrInvalidCiphertext,
		},
		{
			"auth strategy missing callback",
			"auth strategy requires a token callback",
			ErrAuthStrategy,
		},
		{
			"auth strategy missing workspace crn",
			"workspaceCrn is required for oidcFederation",
			ErrAuthStrategy,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := newError("Test", tc.message)
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("errors.Is(err, %v) = false, want true", tc.sentinel)
			}
			if err.Error() != tc.message {
				t.Errorf("Error(): got %q, want %q", err.Error(), tc.message)
			}
			if err.Op != "Test" {
				t.Errorf("Op: got %q, want %q", err.Op, "Test")
			}
		})
	}
}

func TestErrorUnknownMessage(t *testing.T) {
	t.Parallel()

	err := newError("Test", "something completely unexpected happened")

	// Should not match specific sentinels.
	if errors.Is(err, ErrUnknownColumn) {
		t.Error("should not match ErrUnknownColumn")
	}
	if errors.Is(err, ErrMissingIndex) {
		t.Error("should not match ErrMissingIndex")
	}

	// Should match the generic FFI sentinel.
	if !errors.Is(err, ErrFFI) {
		t.Error("should match ErrFFI for unclassified FFI errors")
	}

	var protectErr *Error
	if !errors.As(err, &protectErr) {
		t.Fatal("errors.As should match *Error")
	}
	if protectErr.Err != ErrFFI {
		t.Errorf("Err: got %v, want ErrFFI", protectErr.Err)
	}
}

func TestErrorClientClosed(t *testing.T) {
	t.Parallel()

	err := &Error{Op: "Encrypt", Err: ErrClientClosed, Message: "protect: client is closed"}

	if !errors.Is(err, ErrClientClosed) {
		t.Error("errors.Is(err, ErrClientClosed) = false, want true")
	}
	if err.Error() != "protect: client is closed" {
		t.Errorf("Error(): got %q", err.Error())
	}
}

func TestErrorImplementsErrorInterface(t *testing.T) {
	t.Parallel()

	var e error = &Error{Op: "Test", Message: "test error"}
	if e.Error() != "test error" {
		t.Errorf("Error(): got %q, want %q", e.Error(), "test error")
	}
}

// ---------------------------------------------------------------------------
// Tokenizer and index opts tests
// ---------------------------------------------------------------------------

func TestTokenizer(t *testing.T) {
	t.Parallel()

	t.Run("standard", func(t *testing.T) {
		t.Parallel()
		tok := Tokenizer{Kind: "standard"}
		if tok.Kind != "standard" {
			t.Errorf("Kind: got %q, want %q", tok.Kind, "standard")
		}
		if tok.TokenLength != nil {
			t.Error("TokenLength: expected nil")
		}
	})

	t.Run("ngram", func(t *testing.T) {
		t.Parallel()
		tl := 3
		tok := Tokenizer{Kind: "ngram", TokenLength: &tl}
		if tok.Kind != "ngram" {
			t.Errorf("Kind: got %q, want %q", tok.Kind, "ngram")
		}
		if tok.TokenLength == nil || *tok.TokenLength != 3 {
			t.Errorf("TokenLength: got %v, want 3", tok.TokenLength)
		}
	})
}

func TestMatchIndexOpts(t *testing.T) {
	t.Parallel()

	k := 8
	m := 1024
	includeOriginal := true

	opts := MatchIndexOpts{
		Tokenizer:       &Tokenizer{Kind: "standard"},
		TokenFilters:    []TokenFilter{{Kind: "downcase"}, {Kind: "trim"}},
		K:               &k,
		M:               &m,
		IncludeOriginal: &includeOriginal,
	}

	if opts.Tokenizer.Kind != "standard" {
		t.Errorf("tokenizer kind: got %q, want %q", opts.Tokenizer.Kind, "standard")
	}
	if len(opts.TokenFilters) != 2 {
		t.Errorf("token filters: got %d, want 2", len(opts.TokenFilters))
	}
	if *opts.K != 8 {
		t.Errorf("K: got %d, want 8", *opts.K)
	}
	if *opts.M != 1024 {
		t.Errorf("M: got %d, want 1024", *opts.M)
	}
}

func TestSteVecIndexOpts(t *testing.T) {
	t.Parallel()

	t.Run("basic", func(t *testing.T) {
		t.Parallel()
		opts := SteVecIndexOpts{Prefix: "users"}
		if opts.Prefix != "users" {
			t.Errorf("Prefix: got %q, want %q", opts.Prefix, "users")
		}
	})

	t.Run("with term filters and array index mode", func(t *testing.T) {
		t.Parallel()
		mode := "flatten"
		opts := SteVecIndexOpts{
			Prefix:         "products",
			TermFilters:    []TokenFilter{{Kind: "downcase"}},
			ArrayIndexMode: &mode,
		}
		if opts.Prefix != "products" {
			t.Errorf("Prefix: got %q, want %q", opts.Prefix, "products")
		}
		if len(opts.TermFilters) != 1 {
			t.Errorf("TermFilters: got %d, want 1", len(opts.TermFilters))
		}
		if opts.ArrayIndexMode == nil || *opts.ArrayIndexMode != "flatten" {
			t.Errorf("ArrayIndexMode: got %v, want %q", opts.ArrayIndexMode, "flatten")
		}
	})

	t.Run("json round-trip", func(t *testing.T) {
		t.Parallel()
		mode := "flatten"
		opts := SteVecIndexOpts{
			Prefix:         "test",
			TermFilters:    []TokenFilter{{Kind: "downcase"}},
			ArrayIndexMode: &mode,
		}

		data, err := json.Marshal(opts)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		var decoded SteVecIndexOpts
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}

		if decoded.Prefix != "test" {
			t.Errorf("Prefix: got %q, want %q", decoded.Prefix, "test")
		}
		if decoded.ArrayIndexMode == nil || *decoded.ArrayIndexMode != "flatten" {
			t.Errorf("ArrayIndexMode: got %v, want %q", decoded.ArrayIndexMode, "flatten")
		}
	})
}

// ---------------------------------------------------------------------------
// PlaintextItem and QueryItem tests
// ---------------------------------------------------------------------------

func TestPlaintextItem(t *testing.T) {
	t.Parallel()

	col := ColumnRef{table: "users", column: "email"}
	item := PlaintextItem{
		Column:    col,
		Plaintext: "alice@example.com",
	}

	if item.Column.table != "users" || item.Column.column != "email" {
		t.Errorf("Column: got table=%q column=%q", item.Column.table, item.Column.column)
	}
	if item.Plaintext != "alice@example.com" {
		t.Errorf("Plaintext: got %v, want %q", item.Plaintext, "alice@example.com")
	}
}

func TestQueryItem(t *testing.T) {
	t.Parallel()

	col := ColumnRef{table: "users", column: "name"}
	item := QueryItem{
		Column:    col,
		QueryType: FreeTextSearch,
		Plaintext: "john",
	}

	if item.QueryType != FreeTextSearch {
		t.Errorf("QueryType: got %q, want %q", item.QueryType, FreeTextSearch)
	}
}

// ---------------------------------------------------------------------------
// EncryptConfig structure tests
// ---------------------------------------------------------------------------

func TestEncryptConfigStructure(t *testing.T) {
	t.Parallel()

	castAs := CastAsText
	config := EncryptConfig{
		Version: 1,
		Tables: Tables{
			"users": Table{
				"email": Column{
					CastAs: &castAs,
					Indexes: &Indexes{
						OreIndex: &OreIndexOpts{},
						UniqueIndex: &UniqueIndexOpts{
							TokenFilters: []TokenFilter{{Kind: "downcase"}},
						},
					},
				},
			},
		},
	}

	if config.Version != 1 {
		t.Errorf("version: got %d, want 1", config.Version)
	}

	usersTable, exists := config.Tables["users"]
	if !exists {
		t.Fatal("missing users table")
	}

	emailColumn, exists := usersTable["email"]
	if !exists {
		t.Fatal("missing email column")
	}

	if *emailColumn.CastAs != CastAsText {
		t.Errorf("CastAs: got %v, want %q", *emailColumn.CastAs, CastAsText)
	}

	if emailColumn.Indexes.OreIndex == nil {
		t.Error("expected OreIndex")
	}

	if emailColumn.Indexes.UniqueIndex == nil {
		t.Error("expected UniqueIndex")
	}

	if len(emailColumn.Indexes.UniqueIndex.TokenFilters) != 1 {
		t.Errorf("token filters: got %d, want 1", len(emailColumn.Indexes.UniqueIndex.TokenFilters))
	}

	if emailColumn.Indexes.UniqueIndex.TokenFilters[0].Kind != "downcase" {
		t.Errorf("token filter: got %q, want %q", emailColumn.Indexes.UniqueIndex.TokenFilters[0].Kind, "downcase")
	}
}

// ---------------------------------------------------------------------------
// LockContext tests
// ---------------------------------------------------------------------------

func TestLockContextJSON(t *testing.T) {
	t.Parallel()

	lc := LockContext{IdentityClaim: []string{"user:123", "org:456"}}

	data, err := json.Marshal(lc)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded LockContext
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(decoded.IdentityClaim) != 2 {
		t.Fatalf("IdentityClaim: got %d, want 2", len(decoded.IdentityClaim))
	}
	if decoded.IdentityClaim[0] != "user:123" || decoded.IdentityClaim[1] != "org:456" {
		t.Errorf("IdentityClaim: got %v", decoded.IdentityClaim)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func castPtr(c CastAs) *CastAs {
	return &c
}
