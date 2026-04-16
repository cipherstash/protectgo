package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cipherstash/protectgo/pkg/protect"
)

func main() {
	// Configure encryption settings
	config := protect.EncryptConfig{
		Version: 1,
		Tables: protect.Tables{
			"users": protect.Table{
				"email": protect.Column{
					CastAs: ptr(protect.CastAsText),
					Indexes: &protect.Indexes{
						OreIndex: &protect.OreIndexOpts{},
						UniqueIndex: &protect.UniqueIndexOpts{
							TokenFilters: []protect.TokenFilter{
								{Kind: "downcase"},
							},
						},
					},
				},
				"name": protect.Column{
					CastAs: ptr(protect.CastAsText),
					Indexes: &protect.Indexes{
						MatchIndex: &protect.MatchIndexOpts{
							K:               ptr(6),
							M:               ptr(2048),
							IncludeOriginal: ptr(false),
						},
					},
				},
				"age": protect.Column{
					CastAs: ptr(protect.CastAsNumber),
					Indexes: &protect.Indexes{
						OreIndex: &protect.OreIndexOpts{},
					},
				},
				"active": protect.Column{
					CastAs: ptr(protect.CastAsBoolean),
				},
			},
		},
	}

	// Create client options with optional keyset configuration
	clientOpts := protect.NewClientOptions{
		EncryptConfig: config,
		ClientOpts: &protect.ClientOpts{
			WorkspaceCrn: ptr(os.Getenv("CIPHERSTASH_WORKSPACE_CRN")),
			AccessKey:    ptr(os.Getenv("CIPHERSTASH_ACCESS_KEY")),
			ClientID:     ptr(os.Getenv("CIPHERSTASH_CLIENT_ID")),
			ClientKey:    ptr(os.Getenv("CIPHERSTASH_CLIENT_KEY")),
			Keyset: &protect.KeysetConfig{
				Name: ptr("my-keyset"),
			},
		},
	}

	// Create a new client
	client, err := protect.NewClient(clientOpts)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Free()

	// Example 1: Encrypt a string value
	encryptOpts := protect.EncryptOptions{
		Plaintext: "john.doe@example.com",
		Table:     "users",
		Column:    "email",
	}

	encrypted, err := client.Encrypt(encryptOpts)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}

	fmt.Printf("Encrypted email: %s\n", *encrypted.Ciphertext)
	if encrypted.OreIndex != nil {
		fmt.Printf("ORE index: %v\n", *encrypted.OreIndex)
	}
	if encrypted.UniqueIndex != nil {
		fmt.Printf("Unique index: %s\n", *encrypted.UniqueIndex)
	}

	// Example 2: Encrypt a numeric value
	ageEncrypted, err := client.Encrypt(protect.EncryptOptions{
		Plaintext: 30,
		Table:     "users",
		Column:    "age",
	})
	if err != nil {
		log.Fatalf("Failed to encrypt age: %v", err)
	}

	fmt.Printf("Encrypted age ciphertext: %s\n", *ageEncrypted.Ciphertext)

	// Example 3: Encrypt a boolean value
	activeEncrypted, err := client.Encrypt(protect.EncryptOptions{
		Plaintext: true,
		Table:     "users",
		Column:    "active",
	})
	if err != nil {
		log.Fatalf("Failed to encrypt active: %v", err)
	}

	fmt.Printf("Encrypted active ciphertext: %s\n", *activeEncrypted.Ciphertext)

	// Example 4: Decrypt the value (returns interface{})
	decryptOpts := protect.DecryptOptions{
		Ciphertext: encrypted,
	}

	plaintext, err := client.Decrypt(decryptOpts)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	fmt.Printf("Decrypted email: %v\n", plaintext)

	// Example 5: Check if a value is encrypted
	if protect.IsEncrypted(encrypted) {
		fmt.Println("Value is encrypted")
	}

	if !protect.IsEncrypted("not encrypted") {
		fmt.Println("Plain string is not encrypted")
	}

	// Example 6: Encrypt a query for searching
	queryEncrypted, err := client.EncryptQuery(protect.EncryptQueryOptions{
		Plaintext: "john",
		Column:    "name",
		Table:     "users",
		IndexType: protect.IndexTypeMatch,
		QueryOp:   protect.QueryOpDefault,
	})
	if err != nil {
		log.Fatalf("Failed to encrypt query: %v", err)
	}

	fmt.Printf("Encrypted query match index: %v\n", queryEncrypted.MatchIndex)

	// Example 7: Bulk encryption with mixed types
	bulkEncryptOpts := protect.EncryptBulkOptions{
		Plaintexts: []protect.PlaintextPayload{
			{
				Plaintext: "Alice Smith",
				Table:     "users",
				Column:    "name",
			},
			{
				Plaintext: "Bob Johnson",
				Table:     "users",
				Column:    "name",
			},
		},
	}

	bulkEncrypted, err := client.EncryptBulk(bulkEncryptOpts)
	if err != nil {
		log.Fatalf("Failed to bulk encrypt: %v", err)
	}

	fmt.Printf("Bulk encrypted %d items\n", len(bulkEncrypted))

	// Example 8: Bulk decryption (pass *Encrypted values)
	ciphertexts := make([]protect.BulkDecryptPayload, len(bulkEncrypted))
	for i := range bulkEncrypted {
		ciphertexts[i] = protect.BulkDecryptPayload{
			Ciphertext: &bulkEncrypted[i],
		}
	}

	bulkDecryptOpts := protect.DecryptBulkOptions{
		Ciphertexts: ciphertexts,
	}

	bulkPlaintexts, err := client.DecryptBulk(bulkDecryptOpts)
	if err != nil {
		log.Fatalf("Failed to bulk decrypt: %v", err)
	}

	fmt.Printf("Bulk decrypted values: %v\n", bulkPlaintexts)

	// Example 9: Bulk decryption with fallible results
	fallibleResults, err := client.DecryptBulkFallible(bulkDecryptOpts)
	if err != nil {
		log.Fatalf("Failed to bulk decrypt fallible: %v", err)
	}

	for i, result := range fallibleResults {
		if result.Data != nil {
			fmt.Printf("Result %d: %v\n", i, result.Data)
		} else {
			fmt.Printf("Result %d: Error - %s\n", i, *result.Error)
		}
	}

	// Example 10: Bulk query encryption
	bulkQueryOpts := protect.EncryptQueryBulkOptions{
		Queries: []protect.QueryPayload{
			{
				Plaintext: "alice",
				Column:    "name",
				Table:     "users",
				IndexType: protect.IndexTypeMatch,
			},
			{
				Plaintext: "bob",
				Column:    "name",
				Table:     "users",
				IndexType: protect.IndexTypeMatch,
			},
		},
	}

	bulkQueryEncrypted, err := client.EncryptQueryBulk(bulkQueryOpts)
	if err != nil {
		log.Fatalf("Failed to bulk encrypt queries: %v", err)
	}

	fmt.Printf("Bulk encrypted %d queries\n", len(bulkQueryEncrypted))
}

func ptr[T any](v T) *T {
	return &v
}
