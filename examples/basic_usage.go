package main

import (
	"fmt"
	"log"

	"github.com/cipherstash/protectgo/pkg/protect"
)

func main() {
	// Configure encryption settings
	config := protect.EncryptConfig{
		Version: 1,
		Tables: protect.Tables{
			"users": protect.Table{
				"email": protect.Column{
					CastAs: stringPtr(protect.CastAsText),
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
					CastAs: stringPtr(protect.CastAsText),
					Indexes: &protect.Indexes{
						MatchIndex: &protect.MatchIndexOpts{
							K:               intPtr(6),
							M:               intPtr(2048),
							IncludeOriginal: boolPtr(false),
						},
					},
				},
			},
		},
	}

	// Create client options
	clientOpts := protect.NewClientOptions{
		EncryptConfig: config,
		ClientOpts:    &protect.ClientOpts{
			// These would typically come from environment variables
			// WorkspaceCrn: stringPtr("crn:cipherstash:workspace::..."),
			// AccessKey:    stringPtr("your-access-key"),
			// ClientID:     stringPtr("your-client-id"),
			// ClientKey:    stringPtr("your-client-key"),
		},
	}

	// Create a new client
	client, err := protect.NewClient(clientOpts)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Free()

	// Example 1: Encrypt a single value
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

	// Example 2: Decrypt the value
	decryptOpts := protect.DecryptOptions{
		Ciphertext: *encrypted.Ciphertext,
	}

	plaintext, err := client.Decrypt(decryptOpts)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	fmt.Printf("Decrypted email: %s\n", plaintext)

	// Example 3: Bulk encryption
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

	// Example 4: Bulk decryption
	ciphertexts := make([]protect.BulkDecryptPayload, len(bulkEncrypted))
	for i, enc := range bulkEncrypted {
		ciphertexts[i] = protect.BulkDecryptPayload{
			Ciphertext: *enc.Ciphertext,
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

	// Example 5: Bulk decryption with fallible results
	fallibleResults, err := client.DecryptBulkFallible(bulkDecryptOpts)
	if err != nil {
		log.Fatalf("Failed to bulk decrypt fallible: %v", err)
	}

	for i, result := range fallibleResults {
		if result.Data != nil {
			fmt.Printf("Result %d: %s\n", i, *result.Data)
		} else {
			fmt.Printf("Result %d: Error - %s\n", i, *result.Error)
		}
	}
}

// Helper functions for creating pointers
func stringPtr(s protect.CastAs) *protect.CastAs {
	return &s
}

func intPtr(i int) *int {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}
