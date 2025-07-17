package protect

import (
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
		constant CastAs
		expected string
	}{
		{CastAsBigInt, "big_int"},
		{CastAsBoolean, "boolean"},
		{CastAsDate, "date"},
		{CastAsReal, "real"},
		{CastAsDouble, "double"},
		{CastAsInt, "int"},
		{CastAsSmallInt, "small_int"},
		{CastAsText, "text"},
		{CastAsJsonB, "jsonb"},
	}

	for _, test := range tests {
		if string(test.constant) != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, string(test.constant))
		}
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
		t.Errorf("Expected plaintext 'test@example.com', got '%s'", opts.Plaintext)
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
				Plaintext: "bob@example.com",
				Column:    "email",
				Table:     "users",
			},
		},
	}

	if len(opts.Plaintexts) != 2 {
		t.Errorf("Expected 2 plaintexts, got %d", len(opts.Plaintexts))
	}

	if opts.Plaintexts[0].Plaintext != "alice@example.com" {
		t.Errorf("Expected 'alice@example.com', got '%s'", opts.Plaintexts[0].Plaintext)
	}

	if opts.Plaintexts[1].Plaintext != "bob@example.com" {
		t.Errorf("Expected 'bob@example.com', got '%s'", opts.Plaintexts[1].Plaintext)
	}
}

// TestDecryptResult tests the decrypt result structure
func TestDecryptResult(t *testing.T) {
	// Test successful result
	data := "decrypted data"
	successResult := DecryptResult{
		Data: &data,
	}

	if successResult.Data == nil {
		t.Error("Expected data to be set")
	}

	if *successResult.Data != "decrypted data" {
		t.Errorf("Expected 'decrypted data', got '%s'", *successResult.Data)
	}

	if successResult.Error != nil {
		t.Error("Expected error to be nil for successful result")
	}

	// Test error result
	errorMsg := "decryption failed"
	errorResult := DecryptResult{
		Error: &errorMsg,
	}

	if errorResult.Error == nil {
		t.Error("Expected error to be set")
	}

	if *errorResult.Error != "decryption failed" {
		t.Errorf("Expected 'decryption failed', got '%s'", *errorResult.Error)
	}

	if errorResult.Data != nil {
		t.Error("Expected data to be nil for error result")
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
