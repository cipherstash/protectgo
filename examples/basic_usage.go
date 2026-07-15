package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/cipherstash/protectgo/pkg/protect"
)

// User defines the data model with encryption schema using struct tags.
//
// The `cs` tag defines:
//   - Column name (first value)
//   - Index types: unique, match, ore, ste_vec
//   - Cast type override: cast=number, cast=boolean, etc.
//
// Fields without a `cs` tag are not encrypted.
type User struct {
	ID      int    `json:"id"`
	Email   string `json:"email"   cs:"email,unique(downcase),match"`
	Name    string `json:"name"    cs:"name,match"`
	Age     int    `json:"age"     cs:"age,cast=number,ore"`
	Active  bool   `json:"active"  cs:"active,cast=boolean"`
	Profile any    `json:"profile" cs:"profile,ste_vec(prefix=users/profile)"`
	Role    string `json:"role"` // not encrypted
}

func main() {
	ctx := context.Background()

	// ---------------------------------------------------------------
	// 1. Define schema from struct tags
	// ---------------------------------------------------------------

	users, err := protect.TableSchema("users", User{})
	if err != nil {
		log.Fatalf("Failed to create schema: %v", err)
	}

	// ---------------------------------------------------------------
	// 2. Create client with functional options
	// ---------------------------------------------------------------

	client, err := protect.NewClient(ctx,
		protect.WithSchemas(users),
		protect.WithCredentials(
			os.Getenv("CS_WORKSPACE_CRN"),
			os.Getenv("CS_CLIENT_ACCESS_KEY"),
			os.Getenv("CS_CLIENT_ID"),
			os.Getenv("CS_CLIENT_KEY"),
		),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// ---------------------------------------------------------------
	// Per-user identity federation (optional)
	// ---------------------------------------------------------------
	//
	// WithOIDCFederation makes every encryption and decryption identity-aware
	// without threading any per-operation context through your calls. Return a
	// fresh third-party OIDC access token (a JWT) from your identity provider
	// (Clerk, Auth0, Supabase, ...); the client exchanges it for a CipherStash
	// service token and caches it until expiry. A workspace CRN is required,
	// from WithCredentials or the CS_WORKSPACE_CRN environment variable.
	//
	//	client, err := protect.NewClient(ctx,
	//	    protect.WithSchemas(users),
	//	    protect.WithCredentials(crn, accessKey, clientID, clientKey),
	//	    protect.WithOIDCFederation(func(ctx context.Context) (string, error) {
	//	        return identityProvider.AccessToken(ctx) // your app's IdP JWT
	//	    }),
	//	)

	// ---------------------------------------------------------------
	// Ciphertext format version (optional)
	// ---------------------------------------------------------------
	//
	// The default is EncryptedFormatV2. Select V3 only for databases
	// initialized with the v3 CipherStash database schema:
	//
	//	client, err := protect.NewClient(ctx,
	//	    protect.WithSchemas(users),
	//	    protect.WithEncryptedFormat(protect.EncryptedFormatV3),
	//	)

	// ---------------------------------------------------------------
	// 3. Encrypt and decrypt a model (struct-based)
	// ---------------------------------------------------------------

	user := User{
		ID:     1,
		Email:  "john.doe@example.com",
		Name:   "John Doe",
		Age:    30,
		Active: true,
		Role:   "admin",
	}

	encryptedMap, err := client.EncryptModel(ctx, users, user)
	if err != nil {
		log.Fatalf("Failed to encrypt model: %v", err)
	}

	fmt.Println("Encrypted model:")
	fmt.Printf("  id (plain):    %v\n", encryptedMap["id"])
	fmt.Printf("  role (plain):  %v\n", encryptedMap["role"])
	fmt.Printf("  email:         [encrypted]\n")
	fmt.Printf("  name:          [encrypted]\n")
	fmt.Printf("  age:           [encrypted]\n")
	fmt.Printf("  active:        [encrypted]\n")

	var decryptedUser User
	err = client.DecryptModel(ctx, users, encryptedMap, &decryptedUser)
	if err != nil {
		log.Fatalf("Failed to decrypt model: %v", err)
	}

	fmt.Printf("\nDecrypted model:\n")
	fmt.Printf("  Email: %s\n", decryptedUser.Email)
	fmt.Printf("  Name:  %s\n", decryptedUser.Name)
	fmt.Printf("  Age:   %d\n", decryptedUser.Age)
	fmt.Printf("  Role:  %s\n", decryptedUser.Role)

	// ---------------------------------------------------------------
	// 4. Bulk encrypt and decrypt models (single KMS call)
	// ---------------------------------------------------------------

	userSlice := []User{
		{ID: 1, Email: "alice@example.com", Name: "Alice", Age: 28, Active: true, Role: "admin"},
		{ID: 2, Email: "bob@example.com", Name: "Bob", Age: 35, Active: false, Role: "user"},
	}

	encryptedModels, err := client.BulkEncryptModels(ctx, users, userSlice)
	if err != nil {
		log.Fatalf("Failed to bulk encrypt models: %v", err)
	}

	fmt.Printf("\nBulk encrypted %d models\n", len(encryptedModels))

	var decryptedUsers []User
	err = client.BulkDecryptModels(ctx, users, encryptedModels, &decryptedUsers)
	if err != nil {
		log.Fatalf("Failed to bulk decrypt models: %v", err)
	}

	for _, u := range decryptedUsers {
		fmt.Printf("  %s <%s> (age %d)\n", u.Name, u.Email, u.Age)
	}

	// ---------------------------------------------------------------
	// 5. Single value encryption and decryption
	// ---------------------------------------------------------------

	encrypted, err := client.Encrypt(ctx, users.Column("email"), "john.doe@example.com")
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}

	fmt.Printf("\nEncrypted single value (has unique index: %v)\n", encrypted.UniqueIndex != nil)

	plaintext, err := client.Decrypt(ctx, encrypted)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	fmt.Printf("Decrypted: %v\n", plaintext)

	// ---------------------------------------------------------------
	// 6. Query encryption (for searching encrypted columns)
	// ---------------------------------------------------------------
	//
	// EncryptQuery returns an opaque *protect.QueryTerm. Treat it as a value to
	// bind into your SQL statement — do not inspect its shape. Depending on the
	// column's index configuration it may serialize as a JSON object or a bare
	// JSON string.

	// Exact match query
	queryTerm, err := client.EncryptQuery(ctx, users.Column("email"), protect.Equality, "john.doe@example.com")
	if err != nil {
		log.Fatalf("Failed to encrypt query: %v", err)
	}

	fmt.Printf("\nEncrypted equality query term: %s\n", queryTerm)

	// Full-text search query
	searchTerm, err := client.EncryptQuery(ctx, users.Column("name"), protect.FreeTextSearch, "john")
	if err != nil {
		log.Fatalf("Failed to encrypt search query: %v", err)
	}

	fmt.Printf("Encrypted match query term (%d bytes)\n", len(searchTerm.Bytes()))

	// Range query
	rangeTerm, err := client.EncryptQuery(ctx, users.Column("age"), protect.OrderAndRange, 25)
	if err != nil {
		log.Fatalf("Failed to encrypt range query: %v", err)
	}

	fmt.Printf("Encrypted range query term (%d bytes)\n", len(rangeTerm.Bytes()))

	// Bind a query term into a parameterized SQL statement:
	//
	//   rows, err := db.QueryContext(ctx,
	//       "SELECT * FROM users WHERE email = $1", queryTerm)

	// Bulk query encryption
	bulkQueries, err := client.EncryptQueryBulk(ctx, []protect.QueryItem{
		{Column: users.Column("email"), QueryType: protect.Equality, Plaintext: "alice@example.com"},
		{Column: users.Column("name"), QueryType: protect.FreeTextSearch, Plaintext: "bob"},
	})
	if err != nil {
		log.Fatalf("Failed to bulk encrypt queries: %v", err)
	}

	fmt.Printf("Bulk encrypted %d query terms\n", len(bulkQueries))

	// ---------------------------------------------------------------
	// 7. Bulk encrypt and decrypt individual values
	// ---------------------------------------------------------------

	bulkEncrypted, err := client.EncryptBulk(ctx, []protect.PlaintextItem{
		{Column: users.Column("email"), Plaintext: "alice@example.com"},
		{Column: users.Column("email"), Plaintext: "bob@example.com"},
	})
	if err != nil {
		log.Fatalf("Failed to bulk encrypt: %v", err)
	}

	decryptItems := make([]*protect.Encrypted, len(bulkEncrypted))
	for i := range bulkEncrypted {
		decryptItems[i] = &bulkEncrypted[i]
	}

	bulkPlaintexts, err := client.DecryptBulk(ctx, decryptItems)
	if err != nil {
		log.Fatalf("Failed to bulk decrypt: %v", err)
	}

	fmt.Printf("\nBulk decrypted: %v\n", bulkPlaintexts)

	// ---------------------------------------------------------------
	// 8. Fallible bulk decryption (per-item error handling)
	// ---------------------------------------------------------------

	fallibleResults, err := client.DecryptBulkFallible(ctx, decryptItems)
	if err != nil {
		log.Fatalf("Failed to bulk decrypt fallible: %v", err)
	}

	for i, result := range fallibleResults {
		if result.Err != nil {
			fmt.Printf("  Result %d: error - %s\n", i, result.Err)
		} else {
			fmt.Printf("  Result %d: %v\n", i, result.Data)
		}
	}

	// ---------------------------------------------------------------
	// 9. IsEncrypted validation
	// ---------------------------------------------------------------

	fmt.Printf("\nIsEncrypted(encrypted value): %v\n", protect.IsEncrypted(encrypted))
	fmt.Printf("IsEncrypted(plain string):    %v\n", protect.IsEncrypted("not encrypted"))

	// ---------------------------------------------------------------
	// 10. Identity-aware encryption
	// ---------------------------------------------------------------
	//
	// The simplest way to bind encryption to a user's identity is
	// WithOIDCFederation (see the commented client setup above): every
	// operation then runs under a service token derived from that user's
	// identity provider session, with no per-operation configuration.
	//
	// A lock context additionally ties individual ciphertexts to identity
	// claims. It requires the client to authenticate with an
	// identity-bearing token (i.e. WithOIDCFederation) — with plain access
	// key auth the platform rejects lock-context operations.
	//
	//	lockCtx := &protect.LockContext{IdentityClaim: []string{"sub"}}
	//	enc, err := client.Encrypt(ctx, users.Column("email"), "secret-data",
	//	    protect.WithLockContext(lockCtx))
	//	pt, err := client.Decrypt(ctx, enc, protect.WithLockContext(lockCtx))

	// ---------------------------------------------------------------
	// 11. Error handling with errors.Is
	// ---------------------------------------------------------------

	// Use ColumnOK for safe column lookup without panics.
	if col, ok := users.ColumnOK("nonexistent_column"); ok {
		_, err = client.Encrypt(ctx, col, "test")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	} else {
		fmt.Println("Column not found in schema (caught safely with ColumnOK)")
	}

	// Programmatic error handling with sentinel errors.
	_, err = client.EncryptQuery(ctx, users.Column("email"), protect.OrderAndRange, "test")
	if err != nil {
		switch {
		case errors.Is(err, protect.ErrMissingIndex):
			fmt.Println("Index not configured for this query type (expected)")
		case errors.Is(err, protect.ErrUnknownColumn):
			fmt.Println("Column not found in schema")
		case errors.Is(err, protect.ErrClientClosed):
			fmt.Println("Client was already closed")
		default:
			fmt.Printf("Error: %v\n", err)
		}
	}
}
