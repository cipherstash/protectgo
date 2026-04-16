package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cipherstash/protectgo/pkg/protect"
)

// Define your data model with encryption schema using struct tags.
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
	// ---------------------------------------------------------------
	// 1. Define schema from struct tags and create client
	// ---------------------------------------------------------------

	config := protect.BuildEncryptConfig(
		protect.TableSchema("users", User{}),
	)

	client, err := protect.NewClient(protect.NewClientOptions{
		EncryptConfig: config,
		ClientOpts: &protect.ClientOpts{
			WorkspaceCrn: ptr(os.Getenv("CS_WORKSPACE_CRN")),
			AccessKey:    ptr(os.Getenv("CS_CLIENT_ACCESS_KEY")),
			ClientID:     ptr(os.Getenv("CS_CLIENT_ID")),
			ClientKey:    ptr(os.Getenv("CS_CLIENT_KEY")),
		},
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Free()

	// ---------------------------------------------------------------
	// 2. Encrypt and decrypt a model (struct-based)
	// ---------------------------------------------------------------

	user := User{
		ID:    1,
		Email: "john.doe@example.com",
		Name:  "John Doe",
		Age:   30,
		Active: true,
		Role:  "admin",
	}

	encryptedMap, err := client.EncryptModel(user, "users")
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
	err = client.DecryptModel(encryptedMap, "users", &decryptedUser)
	if err != nil {
		log.Fatalf("Failed to decrypt model: %v", err)
	}

	fmt.Printf("\nDecrypted model:\n")
	fmt.Printf("  Email: %s\n", decryptedUser.Email)
	fmt.Printf("  Name:  %s\n", decryptedUser.Name)
	fmt.Printf("  Age:   %d\n", decryptedUser.Age)
	fmt.Printf("  Role:  %s\n", decryptedUser.Role)

	// ---------------------------------------------------------------
	// 3. Bulk encrypt and decrypt models (single KMS call)
	// ---------------------------------------------------------------

	users := []User{
		{ID: 1, Email: "alice@example.com", Name: "Alice", Age: 28, Active: true, Role: "admin"},
		{ID: 2, Email: "bob@example.com", Name: "Bob", Age: 35, Active: false, Role: "user"},
	}

	encryptedModels, err := client.BulkEncryptModels(users, "users")
	if err != nil {
		log.Fatalf("Failed to bulk encrypt models: %v", err)
	}

	fmt.Printf("\nBulk encrypted %d models\n", len(encryptedModels))

	var decryptedUsers []User
	err = client.BulkDecryptModels(encryptedModels, "users", &decryptedUsers)
	if err != nil {
		log.Fatalf("Failed to bulk decrypt models: %v", err)
	}

	for _, u := range decryptedUsers {
		fmt.Printf("  %s <%s> (age %d)\n", u.Name, u.Email, u.Age)
	}

	// ---------------------------------------------------------------
	// 4. Single value encryption and decryption
	// ---------------------------------------------------------------

	encrypted, err := client.Encrypt(protect.EncryptOptions{
		Plaintext: "john.doe@example.com",
		Table:     "users",
		Column:    "email",
	})
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}

	fmt.Printf("\nEncrypted single value (has unique index: %v)\n", encrypted.UniqueIndex != nil)

	plaintext, err := client.Decrypt(protect.DecryptOptions{
		Ciphertext: encrypted,
	})
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	fmt.Printf("Decrypted: %v\n", plaintext)

	// ---------------------------------------------------------------
	// 5. Query encryption (for searching encrypted columns)
	// ---------------------------------------------------------------

	// Exact match query
	queryResult, err := client.EncryptQuery(protect.EncryptQueryOptions{
		Plaintext: "john.doe@example.com",
		Column:    "email",
		Table:     "users",
		IndexType: protect.IndexTypeUnique,
	})
	if err != nil {
		log.Fatalf("Failed to encrypt query: %v", err)
	}

	fmt.Printf("\nEncrypted equality query (unique index: %s)\n", *queryResult.UniqueIndex)

	// Full-text search query
	searchResult, err := client.EncryptQuery(protect.EncryptQueryOptions{
		Plaintext: "john",
		Column:    "name",
		Table:     "users",
		IndexType: protect.IndexTypeMatch,
	})
	if err != nil {
		log.Fatalf("Failed to encrypt search query: %v", err)
	}

	fmt.Printf("Encrypted match query (bloom filter length: %d)\n", len(*searchResult.MatchIndex))

	// Range query
	rangeResult, err := client.EncryptQuery(protect.EncryptQueryOptions{
		Plaintext: 25,
		Column:    "age",
		Table:     "users",
		IndexType: protect.IndexTypeOre,
	})
	if err != nil {
		log.Fatalf("Failed to encrypt range query: %v", err)
	}

	fmt.Printf("Encrypted range query (ORE index length: %d)\n", len(*rangeResult.OreIndex))

	// Bulk query encryption
	bulkQueries, err := client.EncryptQueryBulk(protect.EncryptQueryBulkOptions{
		Queries: []protect.QueryPayload{
			{Plaintext: "alice@example.com", Column: "email", Table: "users", IndexType: protect.IndexTypeUnique},
			{Plaintext: "bob", Column: "name", Table: "users", IndexType: protect.IndexTypeMatch},
		},
	})
	if err != nil {
		log.Fatalf("Failed to bulk encrypt queries: %v", err)
	}

	fmt.Printf("Bulk encrypted %d queries\n", len(bulkQueries))

	// ---------------------------------------------------------------
	// 6. Bulk encrypt and decrypt individual values
	// ---------------------------------------------------------------

	bulkEncrypted, err := client.EncryptBulk(protect.EncryptBulkOptions{
		Plaintexts: []protect.PlaintextPayload{
			{Plaintext: "alice@example.com", Table: "users", Column: "email"},
			{Plaintext: "bob@example.com", Table: "users", Column: "email"},
		},
	})
	if err != nil {
		log.Fatalf("Failed to bulk encrypt: %v", err)
	}

	ciphertexts := make([]protect.BulkDecryptPayload, len(bulkEncrypted))
	for i := range bulkEncrypted {
		ciphertexts[i] = protect.BulkDecryptPayload{Ciphertext: &bulkEncrypted[i]}
	}

	bulkPlaintexts, err := client.DecryptBulk(protect.DecryptBulkOptions{
		Ciphertexts: ciphertexts,
	})
	if err != nil {
		log.Fatalf("Failed to bulk decrypt: %v", err)
	}

	fmt.Printf("\nBulk decrypted: %v\n", bulkPlaintexts)

	// ---------------------------------------------------------------
	// 7. Fallible bulk decryption (per-item error handling)
	// ---------------------------------------------------------------

	fallibleResults, err := client.DecryptBulkFallible(protect.DecryptBulkOptions{
		Ciphertexts: ciphertexts,
	})
	if err != nil {
		log.Fatalf("Failed to bulk decrypt fallible: %v", err)
	}

	for i, result := range fallibleResults {
		if result.Error != nil {
			fmt.Printf("  Result %d: error - %s\n", i, *result.Error)
		} else {
			fmt.Printf("  Result %d: %v\n", i, result.Data)
		}
	}

	// ---------------------------------------------------------------
	// 8. IsEncrypted validation
	// ---------------------------------------------------------------

	fmt.Printf("\nIsEncrypted(encrypted value): %v\n", protect.IsEncrypted(encrypted))
	fmt.Printf("IsEncrypted(plain string):    %v\n", protect.IsEncrypted("not encrypted"))

	// ---------------------------------------------------------------
	// 9. Identity-aware encryption (lock context)
	// ---------------------------------------------------------------

	lockContext := &protect.LockContext{
		IdentityClaim: []string{"user:12345"},
	}

	lockedEncrypted, err := client.Encrypt(protect.EncryptOptions{
		Plaintext:   "secret-data",
		Table:       "users",
		Column:      "email",
		LockContext: lockContext,
	})
	if err != nil {
		log.Fatalf("Failed to encrypt with lock context: %v", err)
	}

	lockedPlaintext, err := client.Decrypt(protect.DecryptOptions{
		Ciphertext:  lockedEncrypted,
		LockContext: lockContext,
	})
	if err != nil {
		log.Fatalf("Failed to decrypt with lock context: %v", err)
	}

	fmt.Printf("Identity-aware decrypt: %v\n", lockedPlaintext)

	// ---------------------------------------------------------------
	// 10. Structured error handling
	// ---------------------------------------------------------------

	_, err = client.Encrypt(protect.EncryptOptions{
		Plaintext: "test",
		Table:     "users",
		Column:    "nonexistent",
	})
	if err != nil {
		if encErr, ok := err.(*protect.EncryptionError); ok {
			fmt.Printf("\nStructured error:\n")
			fmt.Printf("  Code:    %s\n", encErr.Code)
			fmt.Printf("  Message: %s\n", encErr.Message)
		}
	}
}

func ptr[T any](v T) *T {
	return &v
}
