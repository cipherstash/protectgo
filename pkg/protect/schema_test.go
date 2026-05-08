package protect

import (
	"encoding/json"
	"reflect"
	"testing"
)

// --- Tag parsing tests ---

func TestParseCSTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		tag            string
		wantColumn     string
		wantDirectives []string
	}{
		{
			name:           "column name only",
			tag:            "email",
			wantColumn:     "email",
			wantDirectives: nil,
		},
		{
			name:           "column with single directive",
			tag:            "email,unique",
			wantColumn:     "email",
			wantDirectives: []string{"unique"},
		},
		{
			name:           "column with multiple directives",
			tag:            "email,unique(downcase),match,ore",
			wantColumn:     "email",
			wantDirectives: []string{"unique(downcase)", "match", "ore"},
		},
		{
			name:           "column with cast",
			tag:            "age,cast=number",
			wantColumn:     "age",
			wantDirectives: []string{"cast=number"},
		},
		{
			name:           "match with nested commas in params",
			tag:            "name,match(k=8,m=1024)",
			wantColumn:     "name",
			wantDirectives: []string{"match(k=8,m=1024)"},
		},
		{
			name:           "ste_vec with prefix",
			tag:            "data,ste_vec(prefix=table/col)",
			wantColumn:     "data",
			wantDirectives: []string{"ste_vec(prefix=table/col)"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			col, dirs := parseCSTag(tc.tag)
			if col != tc.wantColumn {
				t.Errorf("column: got %q, want %q", col, tc.wantColumn)
			}
			if len(dirs) != len(tc.wantDirectives) {
				t.Fatalf("directives count: got %d, want %d (got %v)", len(dirs), len(tc.wantDirectives), dirs)
			}
			for i, d := range dirs {
				if d != tc.wantDirectives[i] {
					t.Errorf("directive[%d]: got %q, want %q", i, d, tc.wantDirectives[i])
				}
			}
		})
	}
}

func TestExtractParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		directive  string
		wantName   string
		wantParams string
	}{
		{"ore", "ore", ""},
		{"unique", "unique", ""},
		{"unique(downcase)", "unique", "downcase"},
		{"match(k=8,m=1024)", "match", "k=8,m=1024"},
		{"ste_vec(prefix=users/profile)", "ste_vec", "prefix=users/profile"},
		{"cast=number", "cast", "number"},
		{"cast=json", "cast", "json"},
		{"match", "match", ""},
		{"match(tokenizer=standard)", "match", "tokenizer=standard"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.directive, func(t *testing.T) {
			t.Parallel()

			name, params := extractParams(tc.directive)
			if name != tc.wantName {
				t.Errorf("name: got %q, want %q", name, tc.wantName)
			}
			if params != tc.wantParams {
				t.Errorf("params: got %q, want %q", params, tc.wantParams)
			}
		})
	}
}

// --- parseColumn / index parsing tests ---

func TestParseColumnSimple(t *testing.T) {
	t.Parallel()

	col := parseColumn(nil, reflect.TypeOf(""))
	if col.CastAs == nil || *col.CastAs != CastAsString {
		t.Errorf("cast_as: got %v, want %q", col.CastAs, CastAsString)
	}
	if col.Indexes != nil {
		t.Errorf("indexes: expected nil, got %+v", col.Indexes)
	}
}

func TestParseColumnCastOverride(t *testing.T) {
	t.Parallel()

	col := parseColumn([]string{"cast=number"}, reflect.TypeOf(""))
	if col.CastAs == nil || *col.CastAs != CastAsNumber {
		t.Errorf("cast_as: got %v, want %q", col.CastAs, CastAsNumber)
	}
}

func TestParseColumnUniqueIndex(t *testing.T) {
	t.Parallel()

	col := parseColumn([]string{"unique"}, reflect.TypeOf(""))
	if col.Indexes == nil || col.Indexes.UniqueIndex == nil {
		t.Fatal("expected unique index")
	}
	if len(col.Indexes.UniqueIndex.TokenFilters) != 0 {
		t.Errorf("unique token filters: got %d, want 0", len(col.Indexes.UniqueIndex.TokenFilters))
	}
}

func TestParseColumnUniqueDowncase(t *testing.T) {
	t.Parallel()

	col := parseColumn([]string{"unique(downcase)"}, reflect.TypeOf(""))
	if col.Indexes == nil || col.Indexes.UniqueIndex == nil {
		t.Fatal("expected unique index")
	}
	if len(col.Indexes.UniqueIndex.TokenFilters) != 1 {
		t.Fatalf("unique token filters: got %d, want 1", len(col.Indexes.UniqueIndex.TokenFilters))
	}
	if col.Indexes.UniqueIndex.TokenFilters[0].Kind != "downcase" {
		t.Errorf("token filter kind: got %q, want %q", col.Indexes.UniqueIndex.TokenFilters[0].Kind, "downcase")
	}
}

func TestParseColumnMatchDefaults(t *testing.T) {
	t.Parallel()

	col := parseColumn([]string{"match"}, reflect.TypeOf(""))
	if col.Indexes == nil || col.Indexes.MatchIndex == nil {
		t.Fatal("expected match index")
	}
	mi := col.Indexes.MatchIndex

	if mi.Tokenizer == nil || mi.Tokenizer.Kind != "ngram" {
		t.Errorf("tokenizer kind: got %v, want %q", mi.Tokenizer, "ngram")
	}
	if mi.Tokenizer.TokenLength == nil || *mi.Tokenizer.TokenLength != 3 {
		t.Errorf("token_length: got %v, want 3", mi.Tokenizer.TokenLength)
	}
	if mi.K == nil || *mi.K != 6 {
		t.Errorf("k: got %v, want 6", mi.K)
	}
	if mi.M == nil || *mi.M != 2048 {
		t.Errorf("m: got %v, want 2048", mi.M)
	}
	if mi.IncludeOriginal == nil || *mi.IncludeOriginal != true {
		t.Errorf("include_original: got %v, want true", mi.IncludeOriginal)
	}
	if len(mi.TokenFilters) != 1 || mi.TokenFilters[0].Kind != "downcase" {
		t.Errorf("token_filters: got %v, want [downcase]", mi.TokenFilters)
	}
}

func TestParseColumnMatchCustomOpts(t *testing.T) {
	t.Parallel()

	col := parseColumn([]string{"match(tokenizer=standard,k=8)"}, reflect.TypeOf(""))
	mi := col.Indexes.MatchIndex
	if mi == nil {
		t.Fatal("expected match index")
	}

	if mi.Tokenizer.Kind != "standard" {
		t.Errorf("tokenizer: got %q, want %q", mi.Tokenizer.Kind, "standard")
	}
	if mi.Tokenizer.TokenLength != nil {
		t.Errorf("token_length: got %v, want nil for standard tokenizer", mi.Tokenizer.TokenLength)
	}
	if *mi.K != 8 {
		t.Errorf("k: got %d, want 8", *mi.K)
	}
	if *mi.M != 2048 {
		t.Errorf("m: got %d, want 2048", *mi.M)
	}
}

func TestParseColumnMatchNgramCustomTokenLength(t *testing.T) {
	t.Parallel()

	col := parseColumn([]string{"match(tokenizer=ngram,token_length=4,k=8)"}, reflect.TypeOf(""))
	mi := col.Indexes.MatchIndex
	if mi == nil {
		t.Fatal("expected match index")
	}
	if mi.Tokenizer.Kind != "ngram" {
		t.Errorf("tokenizer: got %q, want %q", mi.Tokenizer.Kind, "ngram")
	}
	if *mi.Tokenizer.TokenLength != 4 {
		t.Errorf("token_length: got %d, want 4", *mi.Tokenizer.TokenLength)
	}
	if *mi.K != 8 {
		t.Errorf("k: got %d, want 8", *mi.K)
	}
}

func TestParseColumnOreIndex(t *testing.T) {
	t.Parallel()

	col := parseColumn([]string{"ore"}, reflect.TypeOf(0))
	if col.Indexes == nil || col.Indexes.OreIndex == nil {
		t.Fatal("expected ore index")
	}
}

func TestParseColumnSteVec(t *testing.T) {
	t.Parallel()

	col := parseColumn([]string{"ste_vec(prefix=users/profile)"}, reflect.TypeOf((*any)(nil)).Elem())
	if col.Indexes == nil || col.Indexes.SteVecIndex == nil {
		t.Fatal("expected ste_vec index")
	}
	if col.Indexes.SteVecIndex.Prefix != "users/profile" {
		t.Errorf("prefix: got %q, want %q", col.Indexes.SteVecIndex.Prefix, "users/profile")
	}
	if col.CastAs == nil || *col.CastAs != CastAsJSON {
		t.Errorf("cast_as: got %v, want %q", col.CastAs, CastAsJSON)
	}
}

func TestParseColumnMultipleIndexes(t *testing.T) {
	t.Parallel()

	col := parseColumn([]string{"unique(downcase)", "match", "ore"}, reflect.TypeOf(""))
	if col.Indexes == nil {
		t.Fatal("expected indexes")
	}
	if col.Indexes.UniqueIndex == nil {
		t.Error("expected unique index")
	}
	if col.Indexes.MatchIndex == nil {
		t.Error("expected match index")
	}
	if col.Indexes.OreIndex == nil {
		t.Error("expected ore index")
	}
}

// --- Type inference tests ---

func TestInferCastAs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		typ      reflect.Type
		wantCast CastAs
	}{
		{"string", reflect.TypeOf(""), CastAsString},
		{"int", reflect.TypeOf(0), CastAsNumber},
		{"int8", reflect.TypeOf(int8(0)), CastAsNumber},
		{"int16", reflect.TypeOf(int16(0)), CastAsNumber},
		{"int32", reflect.TypeOf(int32(0)), CastAsNumber},
		{"int64", reflect.TypeOf(int64(0)), CastAsNumber},
		{"uint", reflect.TypeOf(uint(0)), CastAsNumber},
		{"uint8", reflect.TypeOf(uint8(0)), CastAsNumber},
		{"uint16", reflect.TypeOf(uint16(0)), CastAsNumber},
		{"uint32", reflect.TypeOf(uint32(0)), CastAsNumber},
		{"uint64", reflect.TypeOf(uint64(0)), CastAsNumber},
		{"float32", reflect.TypeOf(float32(0)), CastAsNumber},
		{"float64", reflect.TypeOf(float64(0)), CastAsNumber},
		{"bool", reflect.TypeOf(false), CastAsBoolean},
		{"map", reflect.TypeOf(map[string]any{}), CastAsJSON},
		{"slice", reflect.TypeOf([]string{}), CastAsJSON},
		{"interface", reflect.TypeOf((*any)(nil)).Elem(), CastAsJSON},
		{"*string", reflect.TypeOf((*string)(nil)), CastAsString},
		{"*int", reflect.TypeOf((*int)(nil)), CastAsNumber},
		{"*bool", reflect.TypeOf((*bool)(nil)), CastAsBoolean},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := inferCastAs(tc.typ)
			if got != tc.wantCast {
				t.Errorf("inferCastAs(%v) = %q, want %q", tc.typ, got, tc.wantCast)
			}
		})
	}
}

func TestCastOverrideBeatsInference(t *testing.T) {
	t.Parallel()

	col := parseColumn([]string{"cast=number"}, reflect.TypeOf(""))
	if col.CastAs == nil || *col.CastAs != CastAsNumber {
		t.Errorf("cast_as: got %v, want %q", col.CastAs, CastAsNumber)
	}
}

// --- TableSchema tests ---

type schemaTestUser struct {
	ID      int    `json:"id"`
	Email   string `json:"email"   cs:"email,unique(downcase),match"`
	Name    string `json:"name"    cs:"name,match"`
	Age     int    `json:"age"     cs:"age,cast=number,ore"`
	Active  bool   `json:"active"  cs:"active,cast=boolean"`
	Profile any    `json:"profile" cs:"profile,ste_vec(prefix=users/profile)"`
	Role    string `json:"role"`
}

func TestTableSchemaFullStruct(t *testing.T) {
	t.Parallel()

	td, err := TableSchema("users", schemaTestUser{})
	if err != nil {
		t.Fatalf("TableSchema: %v", err)
	}

	if td.Name() != "users" {
		t.Errorf("table name: got %q, want %q", td.Name(), "users")
	}

	// Should have 5 encrypted columns: email, name, age, active, profile.
	if len(td.columns) != 5 {
		t.Fatalf("columns count: got %d, want 5 (columns: %v)", len(td.columns), columnNames(td.columns))
	}

	// Verify email column.
	email, ok := td.columns["email"]
	if !ok {
		t.Fatal("missing email column")
	}
	if *email.CastAs != CastAsString {
		t.Errorf("email cast_as: got %q, want %q", *email.CastAs, CastAsString)
	}
	if email.Indexes == nil {
		t.Fatal("email indexes: expected non-nil")
	}
	if email.Indexes.UniqueIndex == nil {
		t.Error("email: expected unique index")
	}
	if email.Indexes.MatchIndex == nil {
		t.Error("email: expected match index")
	}

	// Verify age column.
	age, ok := td.columns["age"]
	if !ok {
		t.Fatal("missing age column")
	}
	if *age.CastAs != CastAsNumber {
		t.Errorf("age cast_as: got %q, want %q", *age.CastAs, CastAsNumber)
	}
	if age.Indexes == nil || age.Indexes.OreIndex == nil {
		t.Error("age: expected ore index")
	}

	// Verify profile column.
	profile, ok := td.columns["profile"]
	if !ok {
		t.Fatal("missing profile column")
	}
	if *profile.CastAs != CastAsJSON {
		t.Errorf("profile cast_as: got %q, want %q", *profile.CastAs, CastAsJSON)
	}
	if profile.Indexes == nil || profile.Indexes.SteVecIndex == nil {
		t.Fatal("profile: expected ste_vec index")
	}
	if profile.Indexes.SteVecIndex.Prefix != "users/profile" {
		t.Errorf("profile prefix: got %q, want %q", profile.Indexes.SteVecIndex.Prefix, "users/profile")
	}

	// Verify "Role" is not present (no cs tag).
	if _, ok := td.columns["role"]; ok {
		t.Error("role should not be in columns (no cs tag)")
	}
}

func TestTableSchemaPointerModel(t *testing.T) {
	t.Parallel()

	td, err := TableSchema("users", &schemaTestUser{})
	if err != nil {
		t.Fatalf("TableSchema: %v", err)
	}

	if td.Name() != "users" {
		t.Errorf("table name: got %q, want %q", td.Name(), "users")
	}
	if len(td.columns) != 5 {
		t.Errorf("columns count: got %d, want 5", len(td.columns))
	}
}

type noCSTagSchema struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func TestTableSchemaNoCSTagsEmptyColumns(t *testing.T) {
	t.Parallel()

	td, err := TableSchema("empty", noCSTagSchema{})
	if err != nil {
		t.Fatalf("TableSchema: %v", err)
	}
	if len(td.columns) != 0 {
		t.Errorf("columns count: got %d, want 0", len(td.columns))
	}
}

func TestTableSchemaReturnsErrorOnNonStruct(t *testing.T) {
	t.Parallel()

	_, err := TableSchema("test", "not a struct")
	if err == nil {
		t.Fatal("expected error for non-struct model")
	}
}

func TestTableSchemaReturnsErrorOnNil(t *testing.T) {
	t.Parallel()

	_, err := TableSchema("test", nil)
	if err == nil {
		t.Fatal("expected error for nil model")
	}
}

// --- ColumnRef tests ---

func TestTableDefColumn(t *testing.T) {
	t.Parallel()

	td, err := TableSchema("users", schemaTestUser{})
	if err != nil {
		t.Fatalf("TableSchema: %v", err)
	}

	col := td.Column("email")
	if col.table != "users" {
		t.Errorf("table: got %q, want %q", col.table, "users")
	}
	if col.column != "email" {
		t.Errorf("column: got %q, want %q", col.column, "email")
	}
}

func TestTableDefColumnOK(t *testing.T) {
	t.Parallel()

	td, err := TableSchema("users", schemaTestUser{})
	if err != nil {
		t.Fatalf("TableSchema: %v", err)
	}

	col, ok := td.ColumnOK("email")
	if !ok {
		t.Fatal("expected email column to exist")
	}
	if col.table != "users" || col.column != "email" {
		t.Errorf("ColumnOK: got table=%q column=%q", col.table, col.column)
	}

	_, ok = td.ColumnOK("nonexistent")
	if ok {
		t.Fatal("expected nonexistent column to not exist")
	}
}

func TestTableDefColumnPanicsOnUnknown(t *testing.T) {
	t.Parallel()

	td, err := TableSchema("users", schemaTestUser{})
	if err != nil {
		t.Fatalf("TableSchema: %v", err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for unknown column")
		}
	}()
	td.Column("nonexistent")
}

// --- buildEncryptConfigFromSchemas tests ---

func TestBuildEncryptConfigFromSchemasSingleTable(t *testing.T) {
	t.Parallel()

	td, err := TableSchema("users", schemaTestUser{})
	if err != nil {
		t.Fatalf("TableSchema: %v", err)
	}

	config := buildEncryptConfigFromSchemas([]*TableDef{td})

	if config.Version != 1 {
		t.Errorf("version: got %d, want 1", config.Version)
	}
	if len(config.Tables) != 1 {
		t.Fatalf("tables count: got %d, want 1", len(config.Tables))
	}
	if _, ok := config.Tables["users"]; !ok {
		t.Fatal("missing users table")
	}
}

type schemaTestProduct struct {
	ID    int    `json:"id"`
	Name  string `json:"name" cs:"name,match"`
	Price int    `json:"price" cs:"price,cast=number,ore"`
}

func TestBuildEncryptConfigFromSchemasMultipleTables(t *testing.T) {
	t.Parallel()

	users, err := TableSchema("users", schemaTestUser{})
	if err != nil {
		t.Fatalf("TableSchema users: %v", err)
	}
	products, err := TableSchema("products", schemaTestProduct{})
	if err != nil {
		t.Fatalf("TableSchema products: %v", err)
	}

	config := buildEncryptConfigFromSchemas([]*TableDef{users, products})

	if len(config.Tables) != 2 {
		t.Fatalf("tables count: got %d, want 2", len(config.Tables))
	}
	if _, ok := config.Tables["users"]; !ok {
		t.Error("missing users table")
	}
	if _, ok := config.Tables["products"]; !ok {
		t.Error("missing products table")
	}
}

// --- Edge case tests ---

type skipDashSchema struct {
	ID    int    `json:"id"`
	Email string `json:"email" cs:"-"`
}

func TestTableSchemaSkipDashTag(t *testing.T) {
	t.Parallel()

	td, err := TableSchema("test", skipDashSchema{})
	if err != nil {
		t.Fatalf("TableSchema: %v", err)
	}
	if len(td.columns) != 0 {
		t.Errorf("columns count: got %d, want 0", len(td.columns))
	}
}

type emptyCSSchema struct {
	ID    int    `json:"id"`
	Email string `json:"email" cs:""`
}

func TestTableSchemaSkipEmptyTag(t *testing.T) {
	t.Parallel()

	td, err := TableSchema("test", emptyCSSchema{})
	if err != nil {
		t.Fatalf("TableSchema: %v", err)
	}
	if len(td.columns) != 0 {
		t.Errorf("columns count: got %d, want 0", len(td.columns))
	}
}

type unexportedSchema struct {
	ID    int    `json:"id"`
	Email string `json:"email" cs:"email,unique"`
	//nolint:unused
	secret string `cs:"secret,unique"`
}

func TestTableSchemaSkipsUnexportedFields(t *testing.T) {
	t.Parallel()

	td, err := TableSchema("test", unexportedSchema{})
	if err != nil {
		t.Fatalf("TableSchema: %v", err)
	}
	if len(td.columns) != 1 {
		t.Errorf("columns count: got %d, want 1", len(td.columns))
	}
	if _, ok := td.columns["email"]; !ok {
		t.Error("missing email column")
	}
}

type pointerFieldSchema struct {
	ID    int     `json:"id"`
	Email *string `json:"email" cs:"email,unique"`
	Age   *int    `json:"age" cs:"age,ore"`
	Ok    *bool   `json:"ok" cs:"ok"`
}

func TestTableSchemaPointerFieldTypeInference(t *testing.T) {
	t.Parallel()

	td, err := TableSchema("test", pointerFieldSchema{})
	if err != nil {
		t.Fatalf("TableSchema: %v", err)
	}

	email := td.columns["email"]
	if *email.CastAs != CastAsString {
		t.Errorf("email cast_as: got %q, want %q", *email.CastAs, CastAsString)
	}

	age := td.columns["age"]
	if *age.CastAs != CastAsNumber {
		t.Errorf("age cast_as: got %q, want %q", *age.CastAs, CastAsNumber)
	}

	ok := td.columns["ok"]
	if *ok.CastAs != CastAsBoolean {
		t.Errorf("ok cast_as: got %q, want %q", *ok.CastAs, CastAsBoolean)
	}
}

// --- JSON serialization test ---

func TestBuildEncryptConfigJSONOutput(t *testing.T) {
	t.Parallel()

	type simpleModel struct {
		Email string `json:"email" cs:"email,unique(downcase),match"`
		Age   int    `json:"age" cs:"age,cast=number,ore"`
	}

	td, err := TableSchema("users", simpleModel{})
	if err != nil {
		t.Fatalf("TableSchema: %v", err)
	}
	config := buildEncryptConfigFromSchemas([]*TableDef{td})

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if v, ok := result["v"]; !ok || v != float64(1) {
		t.Errorf("version: got %v, want 1", result["v"])
	}

	tables, ok := result["tables"].(map[string]any)
	if !ok {
		t.Fatal("tables: not a map")
	}

	users, ok := tables["users"].(map[string]any)
	if !ok {
		t.Fatal("users table: not a map")
	}

	emailCol, ok := users["email"].(map[string]any)
	if !ok {
		t.Fatal("email column: not a map")
	}
	if emailCol["cast_as"] != "string" {
		t.Errorf("email cast_as: got %v, want %q", emailCol["cast_as"], "string")
	}

	emailIndexes, ok := emailCol["indexes"].(map[string]any)
	if !ok {
		t.Fatal("email indexes: not a map")
	}
	if _, ok := emailIndexes["unique"]; !ok {
		t.Error("email: missing unique index in JSON")
	}
	if _, ok := emailIndexes["match"]; !ok {
		t.Error("email: missing match index in JSON")
	}

	ageCol, ok := users["age"].(map[string]any)
	if !ok {
		t.Fatal("age column: not a map")
	}
	if ageCol["cast_as"] != "number" {
		t.Errorf("age cast_as: got %v, want %q", ageCol["cast_as"], "number")
	}

	ageIndexes, ok := ageCol["indexes"].(map[string]any)
	if !ok {
		t.Fatal("age indexes: not a map")
	}
	if _, ok := ageIndexes["ore"]; !ok {
		t.Error("age: missing ore index in JSON")
	}
}

// --- Integration: full round-trip test ---

func TestBuildEncryptConfigIntegration(t *testing.T) {
	t.Parallel()

	td, err := TableSchema("users", schemaTestUser{})
	if err != nil {
		t.Fatalf("TableSchema: %v", err)
	}
	config := buildEncryptConfigFromSchemas([]*TableDef{td})

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var roundTripped EncryptConfig
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if roundTripped.Version != 1 {
		t.Errorf("version: got %d, want 1", roundTripped.Version)
	}
	if len(roundTripped.Tables) != 1 {
		t.Fatalf("tables: got %d, want 1", len(roundTripped.Tables))
	}

	usersTable := roundTripped.Tables["users"]
	if len(usersTable) != 5 {
		t.Fatalf("user columns: got %d, want 5", len(usersTable))
	}

	email := usersTable["email"]
	if email.Indexes == nil || email.Indexes.MatchIndex == nil {
		t.Fatal("email match index lost in round-trip")
	}
	if email.Indexes.MatchIndex.Tokenizer.Kind != "ngram" {
		t.Errorf("email match tokenizer: got %q, want %q", email.Indexes.MatchIndex.Tokenizer.Kind, "ngram")
	}
	if *email.Indexes.MatchIndex.K != 6 {
		t.Errorf("email match k: got %d, want 6", *email.Indexes.MatchIndex.K)
	}
}

// --- Test analyzeStruct still works with extended cs tags ---

func TestAnalyzeStructWithExtendedTags(t *testing.T) {
	t.Parallel()

	info, err := analyzeStruct(reflect.TypeOf(schemaTestUser{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(info.EncryptedFields) != 5 {
		t.Fatalf("encrypted fields: got %d, want 5", len(info.EncryptedFields))
	}

	expectedColumns := map[string]bool{
		"email":   true,
		"name":    true,
		"age":     true,
		"active":  true,
		"profile": true,
	}
	for _, ef := range info.EncryptedFields {
		if !expectedColumns[ef.Column] {
			t.Errorf("unexpected column %q (full tag value leaked?)", ef.Column)
		}
	}
}

// --- splitTagParts tests ---

func TestSplitTagParts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  []string
	}{
		{"email", []string{"email"}},
		{"email,unique", []string{"email", "unique"}},
		{"email,match(k=8,m=1024)", []string{"email", "match(k=8,m=1024)"}},
		{"email,match(k=8,m=1024),ore", []string{"email", "match(k=8,m=1024)", "ore"}},
		{"email,unique(downcase),match(tokenizer=ngram,token_length=3,k=6),ore", []string{
			"email", "unique(downcase)", "match(tokenizer=ngram,token_length=3,k=6)", "ore",
		}},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			got := splitTagParts(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("parts count: got %d (%v), want %d (%v)", len(got), got, len(tc.want), tc.want)
			}
			for i, part := range got {
				if part != tc.want[i] {
					t.Errorf("part[%d]: got %q, want %q", i, part, tc.want[i])
				}
			}
		})
	}
}

// --- Programmatic SchemaBuilder tests ---

func TestSchemaBuilderBasic(t *testing.T) {
	t.Parallel()

	td := NewSchema("users").
		Column("email", CastAsString).Equality(TokenFilter{Kind: "downcase"}).FreeTextSearch().Done().
		Column("name", CastAsString).FreeTextSearch().Done().
		Column("age", CastAsNumber).OrderAndRange().Done().
		Build()

	if td.Name() != "users" {
		t.Errorf("name: got %q, want %q", td.Name(), "users")
	}
	if len(td.columns) != 3 {
		t.Fatalf("columns: got %d, want 3", len(td.columns))
	}

	// Verify email
	email := td.columns["email"]
	if *email.CastAs != CastAsString {
		t.Errorf("email cast_as: got %q, want %q", *email.CastAs, CastAsString)
	}
	if email.Indexes == nil || email.Indexes.UniqueIndex == nil {
		t.Fatal("email: expected unique index")
	}
	if len(email.Indexes.UniqueIndex.TokenFilters) != 1 || email.Indexes.UniqueIndex.TokenFilters[0].Kind != "downcase" {
		t.Errorf("email unique token filters: %v", email.Indexes.UniqueIndex.TokenFilters)
	}
	if email.Indexes.MatchIndex == nil {
		t.Error("email: expected match index")
	}

	// Verify age
	age := td.columns["age"]
	if *age.CastAs != CastAsNumber {
		t.Errorf("age cast_as: got %q, want %q", *age.CastAs, CastAsNumber)
	}
	if age.Indexes == nil || age.Indexes.OreIndex == nil {
		t.Error("age: expected ore index")
	}
}

func TestSchemaBuilderSearchableJSON(t *testing.T) {
	t.Parallel()

	td := NewSchema("data").
		Column("metadata", CastAsString).SearchableJSON("data/metadata").Done().
		Build()

	meta := td.columns["metadata"]
	if *meta.CastAs != CastAsJSON {
		t.Errorf("cast_as: got %q, want %q", *meta.CastAs, CastAsJSON)
	}
	if meta.Indexes == nil || meta.Indexes.SteVecIndex == nil {
		t.Fatal("expected ste_vec index")
	}
	if meta.Indexes.SteVecIndex.Prefix != "data/metadata" {
		t.Errorf("prefix: got %q, want %q", meta.Indexes.SteVecIndex.Prefix, "data/metadata")
	}
}

func TestSchemaBuilderFreeTextSearchWithOptions(t *testing.T) {
	t.Parallel()

	td := NewSchema("users").
		Column("bio", CastAsText).FreeTextSearch(WithK(8), WithM(4096), WithTokenizer("standard")).Done().
		Build()

	bio := td.columns["bio"]
	if bio.Indexes == nil || bio.Indexes.MatchIndex == nil {
		t.Fatal("expected match index")
	}
	mi := bio.Indexes.MatchIndex
	if *mi.K != 8 {
		t.Errorf("k: got %d, want 8", *mi.K)
	}
	if *mi.M != 4096 {
		t.Errorf("m: got %d, want 4096", *mi.M)
	}
	if mi.Tokenizer == nil || mi.Tokenizer.Kind != "standard" {
		t.Errorf("tokenizer: got %v, want standard", mi.Tokenizer)
	}
}

func TestSchemaBuilderColumnRef(t *testing.T) {
	t.Parallel()

	td := NewSchema("orders").
		Column("total", CastAsNumber).OrderAndRange().Done().
		Build()

	col := td.Column("total")
	if col.table != "orders" || col.column != "total" {
		t.Errorf("ColumnRef: got table=%q column=%q", col.table, col.column)
	}
}

func TestSchemaBuilderMatchDefaults(t *testing.T) {
	t.Parallel()

	td := NewSchema("t").
		Column("c", CastAsString).FreeTextSearch().Done().
		Build()

	mi := td.columns["c"].Indexes.MatchIndex
	if mi == nil {
		t.Fatal("expected match index")
	}
	if mi.Tokenizer == nil || mi.Tokenizer.Kind != "ngram" {
		t.Errorf("tokenizer: got %v, want ngram", mi.Tokenizer)
	}
	if mi.Tokenizer.TokenLength == nil || *mi.Tokenizer.TokenLength != 3 {
		t.Errorf("token_length: got %v, want 3", mi.Tokenizer.TokenLength)
	}
	if *mi.K != 6 {
		t.Errorf("k: got %d, want 6", *mi.K)
	}
	if *mi.M != 2048 {
		t.Errorf("m: got %d, want 2048", *mi.M)
	}
	if *mi.IncludeOriginal != true {
		t.Errorf("include_original: got %v, want true", *mi.IncludeOriginal)
	}
}

// --- Helpers ---

func columnNames(cols map[string]Column) []string {
	names := make([]string, 0, len(cols))
	for k := range cols {
		names = append(names, k)
	}
	return names
}
