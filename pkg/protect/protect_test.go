package protect

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestIdentifier tests the Identifier creation and JSON marshaling
func TestIdentifier(t *testing.T) {
	ident := NewIdentifier("users", "email")

	if ident.Table != "users" {
		t.Errorf("Expected table 'users', got '%s'", ident.Table)
	}

	if ident.Column != "email" {
		t.Errorf("Expected column 'email', got '%s'", ident.Column)
	}
}

// TestIdentifierJSON tests JSON serialization of Identifier
func TestIdentifierJSON(t *testing.T) {
	ident := NewIdentifier("users", "email")

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

// TestEncryptConfigStructure tests the configuration structure
func TestEncryptConfigStructure(t *testing.T) {
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
							TokenFilters: []TokenFilter{
								{Kind: "downcase"},
							},
						},
					},
				},
			},
		},
	}

	if config.Version != 1 {
		t.Errorf("Expected version 1, got %d", config.Version)
	}

	usersTable, exists := config.Tables["users"]
	if !exists {
		t.Fatal("Expected 'users' table to exist")
	}

	emailColumn, exists := usersTable["email"]
	if !exists {
		t.Fatal("Expected 'email' column to exist")
	}

	if *emailColumn.CastAs != CastAsText {
		t.Errorf("Expected CastAsText, got %v", *emailColumn.CastAs)
	}

	if emailColumn.Indexes.OreIndex == nil {
		t.Error("Expected OreIndex to be configured")
	}

	if emailColumn.Indexes.UniqueIndex == nil {
		t.Error("Expected UniqueIndex to be configured")
	}

	if len(emailColumn.Indexes.UniqueIndex.TokenFilters) != 1 {
		t.Errorf("Expected 1 token filter, got %d", len(emailColumn.Indexes.UniqueIndex.TokenFilters))
	}

	if emailColumn.Indexes.UniqueIndex.TokenFilters[0].Kind != "downcase" {
		t.Errorf("Expected 'downcase' token filter, got '%s'", emailColumn.Indexes.UniqueIndex.TokenFilters[0].Kind)
	}
}

// TestCastAsConstants tests the CastAs constants
func TestCastAsConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant CastAs
		expected string
	}{
		{"BigInt", CastAsBigInt, "bigint"},
		{"Boolean", CastAsBoolean, "boolean"},
		{"Date", CastAsDate, "date"},
		{"Number", CastAsNumber, "number"},
		{"String", CastAsString, "string"},
		{"Text", CastAsText, "text"},
		{"Json", CastAsJson, "json"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.constant) != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, string(tc.constant))
			}
		})
	}
}

// TestEncryptOptions tests the encrypt options structure
func TestEncryptOptions(t *testing.T) {
	lockContext := &LockContext{
		IdentityClaim: []string{"user:123"},
	}

	opts := EncryptOptions{
		Plaintext:   "test@example.com",
		Column:      "email",
		Table:       "users",
		LockContext: lockContext,
	}

	if opts.Plaintext != "test@example.com" {
		t.Errorf("Expected plaintext 'test@example.com', got '%v'", opts.Plaintext)
	}

	if opts.Column != "email" {
		t.Errorf("Expected column 'email', got '%s'", opts.Column)
	}

	if opts.Table != "users" {
		t.Errorf("Expected table 'users', got '%s'", opts.Table)
	}

	if opts.LockContext == nil {
		t.Fatal("Expected LockContext to be set")
	}

	if len(opts.LockContext.IdentityClaim) != 1 {
		t.Errorf("Expected 1 identity claim, got %d", len(opts.LockContext.IdentityClaim))
	}

	if opts.LockContext.IdentityClaim[0] != "user:123" {
		t.Errorf("Expected 'user:123', got '%s'", opts.LockContext.IdentityClaim[0])
	}
}

// TestEncryptOptionsMultiType tests that EncryptOptions accepts multiple plaintext types
func TestEncryptOptionsMultiType(t *testing.T) {
	tests := []struct {
		name      string
		plaintext interface{}
	}{
		{"string", "hello world"},
		{"number_int", 42},
		{"number_float", 3.14},
		{"boolean_true", true},
		{"boolean_false", false},
		{"json_object", map[string]interface{}{"key": "value"}},
		{"json_array", []interface{}{"a", "b", "c"}},
		{"nil", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := EncryptOptions{
				Plaintext: tc.plaintext,
				Column:    "data",
				Table:     "test",
			}

			data, err := json.Marshal(opts)
			if err != nil {
				t.Fatalf("Failed to marshal EncryptOptions with %s plaintext: %v", tc.name, err)
			}

			var decoded map[string]interface{}
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Failed to unmarshal EncryptOptions: %v", err)
			}

			if _, exists := decoded["plaintext"]; !exists && tc.plaintext != nil {
				t.Error("Expected plaintext field in JSON output")
			}
		})
	}
}

// TestBulkEncryptOptions tests the bulk encrypt options structure
func TestBulkEncryptOptions(t *testing.T) {
	opts := EncryptBulkOptions{
		Plaintexts: []PlaintextPayload{
			{
				Plaintext: "alice@example.com",
				Column:    "email",
				Table:     "users",
			},
			{
				Plaintext: 42,
				Column:    "age",
				Table:     "users",
			},
		},
	}

	if len(opts.Plaintexts) != 2 {
		t.Errorf("Expected 2 plaintexts, got %d", len(opts.Plaintexts))
	}

	if opts.Plaintexts[0].Plaintext != "alice@example.com" {
		t.Errorf("Expected 'alice@example.com', got '%v'", opts.Plaintexts[0].Plaintext)
	}

	if opts.Plaintexts[1].Plaintext != 42 {
		t.Errorf("Expected 42, got '%v'", opts.Plaintexts[1].Plaintext)
	}
}

// TestDecryptOptions tests the decrypt options structure with Encrypted ciphertext
func TestDecryptOptions(t *testing.T) {
	ct := "encrypted-data"
	encrypted := &Encrypted{
		Identifier: NewIdentifier("users", "email"),
		Version:    1,
		Ciphertext: &ct,
	}

	opts := DecryptOptions{
		Ciphertext: encrypted,
	}

	if opts.Ciphertext == nil {
		t.Fatal("Expected Ciphertext to be set")
	}

	if opts.Ciphertext.Version != 1 {
		t.Errorf("Expected version 1, got %d", opts.Ciphertext.Version)
	}

	if *opts.Ciphertext.Ciphertext != "encrypted-data" {
		t.Errorf("Expected 'encrypted-data', got '%s'", *opts.Ciphertext.Ciphertext)
	}
}

// TestDecryptOptionsJSON tests JSON serialization of DecryptOptions
func TestDecryptOptionsJSON(t *testing.T) {
	ct := "encrypted-data"
	encrypted := &Encrypted{
		Identifier: NewIdentifier("users", "email"),
		Version:    1,
		Ciphertext: &ct,
	}

	opts := DecryptOptions{
		Ciphertext: encrypted,
	}

	data, err := json.Marshal(opts)
	if err != nil {
		t.Fatalf("Failed to marshal DecryptOptions: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal DecryptOptions: %v", err)
	}

	ciphertext, ok := decoded["ciphertext"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected ciphertext to be an object")
	}

	if ciphertext["c"] != "encrypted-data" {
		t.Errorf("Expected ciphertext.c to be 'encrypted-data', got '%v'", ciphertext["c"])
	}
}

// TestBulkDecryptPayload tests the bulk decrypt payload with Encrypted ciphertext
func TestBulkDecryptPayload(t *testing.T) {
	ct := "encrypted-data"
	encrypted := &Encrypted{
		Identifier: NewIdentifier("users", "email"),
		Version:    1,
		Ciphertext: &ct,
	}

	payload := BulkDecryptPayload{
		Ciphertext: encrypted,
	}

	if payload.Ciphertext == nil {
		t.Fatal("Expected Ciphertext to be set")
	}

	if *payload.Ciphertext.Ciphertext != "encrypted-data" {
		t.Errorf("Expected 'encrypted-data', got '%s'", *payload.Ciphertext.Ciphertext)
	}
}

// TestDecryptResult tests the decrypt result structure with interface{} data
func TestDecryptResult(t *testing.T) {
	t.Run("string data", func(t *testing.T) {
		result := DecryptResult{
			Data: "decrypted data",
		}

		if result.Data == nil {
			t.Error("Expected data to be set")
		}

		if result.Data != "decrypted data" {
			t.Errorf("Expected 'decrypted data', got '%v'", result.Data)
		}

		if result.Error != nil {
			t.Error("Expected error to be nil for successful result")
		}
	})

	t.Run("numeric data", func(t *testing.T) {
		result := DecryptResult{
			Data: 42.0,
		}

		if result.Data != 42.0 {
			t.Errorf("Expected 42.0, got '%v'", result.Data)
		}
	})

	t.Run("boolean data", func(t *testing.T) {
		result := DecryptResult{
			Data: true,
		}

		if result.Data != true {
			t.Errorf("Expected true, got '%v'", result.Data)
		}
	})

	t.Run("nil data", func(t *testing.T) {
		result := DecryptResult{
			Data: nil,
		}

		if result.Data != nil {
			t.Error("Expected data to be nil")
		}
	})

	t.Run("error result", func(t *testing.T) {
		errorMsg := "decryption failed"
		result := DecryptResult{
			Error: &errorMsg,
		}

		if result.Error == nil {
			t.Error("Expected error to be set")
		}

		if *result.Error != "decryption failed" {
			t.Errorf("Expected 'decryption failed', got '%s'", *result.Error)
		}

		if result.Data != nil {
			t.Error("Expected data to be nil for error result")
		}
	})
}

// TestDecryptResultJSON tests JSON round-trip of DecryptResult with multi-type data
func TestDecryptResultJSON(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"string", `{"data":"hello"}`},
		{"number", `{"data":42}`},
		{"boolean", `{"data":true}`},
		{"null", `{"data":null}`},
		{"error", `{"error":"failed"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var result DecryptResult
			if err := json.Unmarshal([]byte(tc.json), &result); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}
		})
	}
}

// TestTokenizer tests the tokenizer structure
func TestTokenizer(t *testing.T) {
	// Test standard tokenizer
	standardTokenizer := Tokenizer{
		Kind: "standard",
	}

	if standardTokenizer.Kind != "standard" {
		t.Errorf("Expected 'standard', got '%s'", standardTokenizer.Kind)
	}

	if standardTokenizer.TokenLength != nil {
		t.Error("Expected TokenLength to be nil for standard tokenizer")
	}

	// Test ngram tokenizer
	tokenLength := 3
	ngramTokenizer := Tokenizer{
		Kind:        "ngram",
		TokenLength: &tokenLength,
	}

	if ngramTokenizer.Kind != "ngram" {
		t.Errorf("Expected 'ngram', got '%s'", ngramTokenizer.Kind)
	}

	if ngramTokenizer.TokenLength == nil {
		t.Error("Expected TokenLength to be set for ngram tokenizer")
	}

	if *ngramTokenizer.TokenLength != 3 {
		t.Errorf("Expected token length 3, got %d", *ngramTokenizer.TokenLength)
	}
}

// TestMatchIndexOpts tests the match index options
func TestMatchIndexOpts(t *testing.T) {
	k := 8
	m := 1024
	includeOriginal := true

	matchOpts := MatchIndexOpts{
		Tokenizer: &Tokenizer{
			Kind: "standard",
		},
		TokenFilters: []TokenFilter{
			{Kind: "downcase"},
			{Kind: "trim"},
		},
		K:               &k,
		M:               &m,
		IncludeOriginal: &includeOriginal,
	}

	if matchOpts.Tokenizer == nil {
		t.Error("Expected tokenizer to be set")
	}

	if matchOpts.Tokenizer.Kind != "standard" {
		t.Errorf("Expected 'standard' tokenizer, got '%s'", matchOpts.Tokenizer.Kind)
	}

	if len(matchOpts.TokenFilters) != 2 {
		t.Errorf("Expected 2 token filters, got %d", len(matchOpts.TokenFilters))
	}

	if matchOpts.TokenFilters[0].Kind != "downcase" {
		t.Errorf("Expected 'downcase', got '%s'", matchOpts.TokenFilters[0].Kind)
	}

	if matchOpts.TokenFilters[1].Kind != "trim" {
		t.Errorf("Expected 'trim', got '%s'", matchOpts.TokenFilters[1].Kind)
	}

	if matchOpts.K == nil || *matchOpts.K != 8 {
		t.Errorf("Expected K to be 8, got %v", matchOpts.K)
	}

	if matchOpts.M == nil || *matchOpts.M != 1024 {
		t.Errorf("Expected M to be 1024, got %v", matchOpts.M)
	}

	if matchOpts.IncludeOriginal == nil || *matchOpts.IncludeOriginal != true {
		t.Errorf("Expected IncludeOriginal to be true, got %v", matchOpts.IncludeOriginal)
	}
}

// TestSteVecIndexOpts tests the SteVec index options with new fields
func TestSteVecIndexOpts(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		opts := SteVecIndexOpts{
			Prefix: "users",
		}

		if opts.Prefix != "users" {
			t.Errorf("Expected prefix 'users', got '%s'", opts.Prefix)
		}

		if opts.TermFilters != nil {
			t.Error("Expected TermFilters to be nil")
		}

		if opts.ArrayIndexMode != nil {
			t.Error("Expected ArrayIndexMode to be nil")
		}
	})

	t.Run("with term filters and array index mode", func(t *testing.T) {
		arrayMode := "flatten"
		opts := SteVecIndexOpts{
			Prefix: "products",
			TermFilters: []TokenFilter{
				{Kind: "downcase"},
				{Kind: "trim"},
			},
			ArrayIndexMode: &arrayMode,
		}

		if opts.Prefix != "products" {
			t.Errorf("Expected prefix 'products', got '%s'", opts.Prefix)
		}

		if len(opts.TermFilters) != 2 {
			t.Errorf("Expected 2 term filters, got %d", len(opts.TermFilters))
		}

		if opts.TermFilters[0].Kind != "downcase" {
			t.Errorf("Expected 'downcase', got '%s'", opts.TermFilters[0].Kind)
		}

		if opts.ArrayIndexMode == nil || *opts.ArrayIndexMode != "flatten" {
			t.Errorf("Expected ArrayIndexMode 'flatten', got %v", opts.ArrayIndexMode)
		}
	})

	t.Run("json round-trip", func(t *testing.T) {
		arrayMode := "flatten"
		opts := SteVecIndexOpts{
			Prefix: "test",
			TermFilters: []TokenFilter{
				{Kind: "downcase"},
			},
			ArrayIndexMode: &arrayMode,
		}

		data, err := json.Marshal(opts)
		if err != nil {
			t.Fatalf("Failed to marshal: %v", err)
		}

		var decoded SteVecIndexOpts
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}

		if decoded.Prefix != "test" {
			t.Errorf("Expected prefix 'test', got '%s'", decoded.Prefix)
		}

		if len(decoded.TermFilters) != 1 {
			t.Errorf("Expected 1 term filter, got %d", len(decoded.TermFilters))
		}

		if decoded.ArrayIndexMode == nil || *decoded.ArrayIndexMode != "flatten" {
			t.Errorf("Expected ArrayIndexMode 'flatten', got %v", decoded.ArrayIndexMode)
		}
	})
}

// TestEncryptedStruct tests the Encrypted struct without Kind field
func TestEncryptedStruct(t *testing.T) {
	ct := "ciphertext-value"
	ore := []string{"ore1", "ore2"}
	match := []uint16{1, 2, 3}
	unique := "unique-hash"

	encrypted := Encrypted{
		Identifier:  NewIdentifier("users", "email"),
		Version:     1,
		Ciphertext:  &ct,
		OreIndex:    &ore,
		MatchIndex:  &match,
		UniqueIndex: &unique,
	}

	if encrypted.Identifier.Table != "users" {
		t.Errorf("Expected table 'users', got '%s'", encrypted.Identifier.Table)
	}

	if encrypted.Version != 1 {
		t.Errorf("Expected version 1, got %d", encrypted.Version)
	}

	if *encrypted.Ciphertext != "ciphertext-value" {
		t.Errorf("Expected 'ciphertext-value', got '%s'", *encrypted.Ciphertext)
	}
}

// TestEncryptedJSON tests JSON serialization of Encrypted (no Kind field)
func TestEncryptedJSON(t *testing.T) {
	ct := "ciphertext-value"
	encrypted := Encrypted{
		Identifier: NewIdentifier("users", "email"),
		Version:    1,
		Ciphertext: &ct,
	}

	data, err := json.Marshal(encrypted)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify Kind field is not present
	if _, exists := decoded["k"]; exists {
		t.Error("Expected 'k' (Kind) field to not be present in JSON output")
	}

	// Verify expected fields
	if decoded["c"] != "ciphertext-value" {
		t.Errorf("Expected c='ciphertext-value', got '%v'", decoded["c"])
	}

	// Version should be present
	if decoded["v"] == nil {
		t.Error("Expected 'v' field to be present")
	}
}

// TestKeysetConfig tests the KeysetConfig structure
func TestKeysetConfig(t *testing.T) {
	t.Run("with name", func(t *testing.T) {
		name := "my-keyset"
		config := KeysetConfig{
			Name: &name,
		}

		if config.Name == nil || *config.Name != "my-keyset" {
			t.Errorf("Expected name 'my-keyset', got %v", config.Name)
		}

		if config.ID != nil {
			t.Error("Expected ID to be nil")
		}
	})

	t.Run("with id", func(t *testing.T) {
		id := "keyset-123"
		config := KeysetConfig{
			ID: &id,
		}

		if config.ID == nil || *config.ID != "keyset-123" {
			t.Errorf("Expected id 'keyset-123', got %v", config.ID)
		}

		if config.Name != nil {
			t.Error("Expected Name to be nil")
		}
	})

	t.Run("json omitempty", func(t *testing.T) {
		name := "test"
		config := KeysetConfig{
			Name: &name,
		}

		data, err := json.Marshal(config)
		if err != nil {
			t.Fatalf("Failed to marshal: %v", err)
		}

		var decoded map[string]interface{}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}

		if _, exists := decoded["id"]; exists {
			t.Error("Expected 'id' to be omitted when nil")
		}
	})
}

// TestClientOptsWithKeyset tests ClientOpts includes Keyset field
func TestClientOptsWithKeyset(t *testing.T) {
	keysetName := "my-keyset"
	opts := ClientOpts{
		Keyset: &KeysetConfig{
			Name: &keysetName,
		},
	}

	data, err := json.Marshal(opts)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	keyset, ok := decoded["keyset"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected keyset to be an object")
	}

	if keyset["name"] != "my-keyset" {
		t.Errorf("Expected keyset.name='my-keyset', got '%v'", keyset["name"])
	}
}

// TestQueryOpConstants tests the QueryOp constants
func TestQueryOpConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant QueryOp
		expected string
	}{
		{"Default", QueryOpDefault, "default"},
		{"SteVecSelector", QueryOpSteVecSelector, "ste_vec_selector"},
		{"SteVecTerm", QueryOpSteVecTerm, "ste_vec_term"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.constant) != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, string(tc.constant))
			}
		})
	}
}

// TestIndexTypeConstants tests the IndexType constants
func TestIndexTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant IndexType
		expected string
	}{
		{"Ore", IndexTypeOre, "ore"},
		{"Unique", IndexTypeUnique, "unique"},
		{"Match", IndexTypeMatch, "match"},
		{"SteVec", IndexTypeSteVec, "ste_vec"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.constant) != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, string(tc.constant))
			}
		})
	}
}

// TestEncryptQueryOptions tests the EncryptQueryOptions structure
func TestEncryptQueryOptions(t *testing.T) {
	opts := EncryptQueryOptions{
		Plaintext: "search-term",
		Column:    "email",
		Table:     "users",
		IndexType: IndexTypeMatch,
		QueryOp:   QueryOpDefault,
	}

	if opts.Plaintext != "search-term" {
		t.Errorf("Expected plaintext 'search-term', got '%v'", opts.Plaintext)
	}

	if opts.IndexType != IndexTypeMatch {
		t.Errorf("Expected IndexTypeMatch, got '%s'", opts.IndexType)
	}

	if opts.QueryOp != QueryOpDefault {
		t.Errorf("Expected QueryOpDefault, got '%s'", opts.QueryOp)
	}
}

// TestEncryptQueryOptionsJSON tests JSON serialization of EncryptQueryOptions
func TestEncryptQueryOptionsJSON(t *testing.T) {
	opts := EncryptQueryOptions{
		Plaintext: "test",
		Column:    "email",
		Table:     "users",
		IndexType: IndexTypeOre,
	}

	data, err := json.Marshal(opts)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded["indexType"] != "ore" {
		t.Errorf("Expected indexType='ore', got '%v'", decoded["indexType"])
	}

	// queryOp should be omitted when zero value
	if _, exists := decoded["queryOp"]; exists {
		t.Error("Expected queryOp to be omitted when empty")
	}
}

// TestQueryPayload tests the QueryPayload structure
func TestQueryPayload(t *testing.T) {
	payload := QueryPayload{
		Plaintext: "search",
		Column:    "name",
		Table:     "users",
		IndexType: IndexTypeSteVec,
		QueryOp:   QueryOpSteVecTerm,
	}

	if payload.IndexType != IndexTypeSteVec {
		t.Errorf("Expected IndexTypeSteVec, got '%s'", payload.IndexType)
	}

	if payload.QueryOp != QueryOpSteVecTerm {
		t.Errorf("Expected QueryOpSteVecTerm, got '%s'", payload.QueryOp)
	}
}

// TestEncryptQueryBulkOptions tests the EncryptQueryBulkOptions structure
func TestEncryptQueryBulkOptions(t *testing.T) {
	opts := EncryptQueryBulkOptions{
		Queries: []QueryPayload{
			{
				Plaintext: "term1",
				Column:    "email",
				Table:     "users",
				IndexType: IndexTypeMatch,
			},
			{
				Plaintext: "term2",
				Column:    "name",
				Table:     "users",
				IndexType: IndexTypeOre,
			},
		},
	}

	if len(opts.Queries) != 2 {
		t.Errorf("Expected 2 queries, got %d", len(opts.Queries))
	}

	if opts.Queries[0].Plaintext != "term1" {
		t.Errorf("Expected 'term1', got '%v'", opts.Queries[0].Plaintext)
	}

	if opts.Queries[1].IndexType != IndexTypeOre {
		t.Errorf("Expected IndexTypeOre, got '%s'", opts.Queries[1].IndexType)
	}
}

// TestEncryptionError tests the EncryptionError type
func TestEncryptionError(t *testing.T) {
	err := &EncryptionError{
		Code:    ErrUnknownColumn,
		Message: "column 'foo' not found in Encrypt config",
	}

	if err.Error() != "column 'foo' not found in Encrypt config" {
		t.Errorf("Expected error message, got '%s'", err.Error())
	}

	if err.Code != ErrUnknownColumn {
		t.Errorf("Expected ErrUnknownColumn, got '%s'", err.Code)
	}

	// Test that it implements the error interface
	var e error = err
	if e == nil {
		t.Error("Expected non-nil error")
	}
}

// TestEncryptionErrorUnwrap tests that EncryptionError can be matched with errors.As
func TestEncryptionErrorUnwrap(t *testing.T) {
	err := newEncryptionError("column 'foo' not found in Encrypt config")

	var encErr *EncryptionError
	if !errors.As(err, &encErr) {
		t.Error("Expected errors.As to match EncryptionError")
	}

	if encErr.Code != ErrUnknownColumn {
		t.Errorf("Expected ErrUnknownColumn, got '%s'", encErr.Code)
	}
}

// TestInferErrorCode tests the error code inference from messages
func TestInferErrorCode(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		expected ErrorCode
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
			ErrInvalidJsonPath,
		},
		{
			"ste_vec requires json cast_as",
			"ste_vec index requires cast_as to be json",
			ErrSteVecRequiresJsonCastAs,
		},
		{
			"unknown error",
			"something completely unexpected happened",
			ErrUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code := inferErrorCode(tc.message)
			if code != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, code)
			}
		})
	}
}

// TestNewEncryptionError tests the newEncryptionError constructor
func TestNewEncryptionError(t *testing.T) {
	err := newEncryptionError("column 'email' not found in Encrypt config")

	if err.Code != ErrUnknownColumn {
		t.Errorf("Expected ErrUnknownColumn, got '%s'", err.Code)
	}

	if err.Message != "column 'email' not found in Encrypt config" {
		t.Errorf("Unexpected message: '%s'", err.Message)
	}
}

// TestPlaintextPayloadMultiType tests PlaintextPayload with different types
func TestPlaintextPayloadMultiType(t *testing.T) {
	tests := []struct {
		name      string
		plaintext interface{}
	}{
		{"string", "hello"},
		{"number", 42},
		{"boolean", true},
		{"json", map[string]interface{}{"nested": "value"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := PlaintextPayload{
				Plaintext: tc.plaintext,
				Column:    "data",
				Table:     "test",
			}

			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}

			var decoded map[string]interface{}
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			if decoded["plaintext"] == nil {
				t.Error("Expected plaintext to be present")
			}
		})
	}
}
