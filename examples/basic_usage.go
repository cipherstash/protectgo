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
			},
		},
	}

	// Create client options
	clientOpts := protect.NewClientOptions{
		EncryptConfig: config,
		ClientOpts: &protect.ClientOpts{
			WorkspaceCrn: ptr(os.Getenv("CIPHERSTASH_WORKSPACE_CRN")),
			AccessKey:    ptr(os.Getenv("CIPHERSTASH_ACCESS_KEY")),
			ClientID:     ptr(os.Getenv("CIPHERSTASH_CLIENT_ID")),
			ClientKey:    ptr(os.Getenv("CIPHERSTASH_CLIENT_KEY")),
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

func ptr[T any](v T) *T {
	return &v
}
