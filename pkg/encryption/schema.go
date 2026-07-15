package encryption

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// TableDef holds a parsed table schema. It is the primary reference for
// table and column identification throughout the API. Create one with
// TableSchema (from struct tags) or NewSchema (programmatic builder).
type TableDef struct {
	name    string
	columns map[string]Column
}

// Name returns the table name.
func (td *TableDef) Name() string {
	return td.name
}

// Column returns a [ColumnRef] for the named column in this table.
// It panics if the column name is not defined in the schema, since
// this indicates a programming error that should be caught at init time.
//
// For a non-panicking alternative, use [TableDef.ColumnOK].
func (td *TableDef) Column(name string) ColumnRef {
	if _, ok := td.columns[name]; !ok {
		panic(fmt.Sprintf("encryption: column %q not found in table %q", name, td.name))
	}
	return ColumnRef{table: td.name, column: name}
}

// ColumnOK returns a [ColumnRef] for the named column and a boolean indicating
// whether the column exists in the schema. Unlike [TableDef.Column], it does
// not panic on unknown columns.
func (td *TableDef) ColumnOK(name string) (ColumnRef, bool) {
	if _, ok := td.columns[name]; !ok {
		return ColumnRef{}, false
	}
	return ColumnRef{table: td.name, column: name}, true
}

// TableSchema creates a table schema definition by parsing `cs` struct tags
// on the given model. The model parameter must be a struct value or pointer
// to a struct.
func TableSchema(tableName string, model any) (*TableDef, error) {
	typ := reflect.TypeOf(model)
	if typ == nil {
		return nil, fmt.Errorf("encryption.TableSchema: model must not be nil")
	}
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return nil, fmt.Errorf("encryption.TableSchema: model must be a struct, got %s", typ.Kind())
	}

	columns := make(map[string]Column)

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)

		// Skip unexported fields.
		if !field.IsExported() {
			continue
		}

		csTag, hasCS := field.Tag.Lookup("cs")
		if !hasCS || csTag == "" || csTag == "-" {
			continue
		}

		columnName, directives := parseCSTag(csTag)
		if columnName == "" || columnName == "-" {
			continue
		}

		columns[columnName] = parseColumn(directives, field.Type)
	}

	return &TableDef{
		name:    tableName,
		columns: columns,
	}, nil
}

// ---------------------------------------------------------------------------
// Programmatic schema builder
// ---------------------------------------------------------------------------

// SchemaBuilder constructs a TableDef programmatically.
type SchemaBuilder struct {
	name    string
	columns map[string]Column
}

// ColumnBuilder configures a single column within a SchemaBuilder.
type ColumnBuilder struct {
	parent  *SchemaBuilder
	name    string
	castAs  CastAs
	indexes Indexes
}

// MatchOption configures optional parameters for a match (free-text search) index.
type MatchOption func(*MatchIndexOpts)

// WithK sets the number of hash functions for the bloom filter.
func WithK(k int) MatchOption {
	return func(o *MatchIndexOpts) { o.K = &k }
}

// WithM sets the size of the bloom filter in bits.
func WithM(m int) MatchOption {
	return func(o *MatchIndexOpts) { o.M = &m }
}

// WithTokenizer sets the tokenizer kind (e.g., "ngram", "standard").
func WithTokenizer(kind string) MatchOption {
	return func(o *MatchIndexOpts) {
		if o.Tokenizer == nil {
			o.Tokenizer = &Tokenizer{}
		}
		o.Tokenizer.Kind = kind
	}
}

// WithTokenLength sets the token length for the ngram tokenizer.
func WithTokenLength(n int) MatchOption {
	return func(o *MatchIndexOpts) {
		if o.Tokenizer == nil {
			o.Tokenizer = &Tokenizer{}
		}
		o.Tokenizer.TokenLength = &n
	}
}

// WithIncludeOriginal controls whether the original value is included in the index.
func WithIncludeOriginal(include bool) MatchOption {
	return func(o *MatchIndexOpts) { o.IncludeOriginal = &include }
}

// NewSchema starts building a table schema with the given name.
func NewSchema(tableName string) *SchemaBuilder {
	return &SchemaBuilder{
		name:    tableName,
		columns: make(map[string]Column),
	}
}

// Column begins configuring a new encrypted column.
func (b *SchemaBuilder) Column(name string, castAs CastAs) *ColumnBuilder {
	return &ColumnBuilder{
		parent: b,
		name:   name,
		castAs: castAs,
	}
}

// Equality adds a unique (HMAC) index to the column, with optional token filters.
func (cb *ColumnBuilder) Equality(filters ...TokenFilter) *ColumnBuilder {
	cb.indexes.UniqueIndex = &UniqueIndexOpts{TokenFilters: filters}
	return cb
}

// FreeTextSearch adds a match (bloom filter) index to the column.
func (cb *ColumnBuilder) FreeTextSearch(optFns ...MatchOption) *ColumnBuilder {
	opts := defaultMatchOpts()
	for _, fn := range optFns {
		fn(opts)
	}
	cb.indexes.MatchIndex = opts
	return cb
}

// OrderAndRange adds an ORE index to the column for range and ordering queries.
func (cb *ColumnBuilder) OrderAndRange() *ColumnBuilder {
	cb.indexes.OreIndex = &OreIndexOpts{}
	return cb
}

// SearchableJSON adds an ste_vec index and sets the cast type to JSON.
func (cb *ColumnBuilder) SearchableJSON(prefix string) *ColumnBuilder {
	cb.castAs = CastAsJSON
	cb.indexes.SteVecIndex = &SteVecIndexOpts{Prefix: prefix}
	return cb
}

// Done finalizes the column and returns the parent SchemaBuilder.
func (cb *ColumnBuilder) Done() *SchemaBuilder {
	ca := cb.castAs
	col := Column{
		CastAs:  &ca,
		Indexes: &cb.indexes,
	}
	cb.parent.columns[cb.name] = col
	return cb.parent
}

// Build creates the TableDef from the builder configuration.
func (b *SchemaBuilder) Build() *TableDef {
	return &TableDef{
		name:    b.name,
		columns: b.columns,
	}
}

// defaultMatchOpts returns the default MatchIndexOpts matching the TypeScript SDK.
func defaultMatchOpts() *MatchIndexOpts {
	tokenLength := 3
	k := 6
	m := 2048
	includeOriginal := true
	return &MatchIndexOpts{
		Tokenizer: &Tokenizer{
			Kind:        "ngram",
			TokenLength: &tokenLength,
		},
		TokenFilters:    []TokenFilter{{Kind: "downcase"}},
		K:               &k,
		M:               &m,
		IncludeOriginal: &includeOriginal,
	}
}

// ---------------------------------------------------------------------------
// Tag parsing (internal, unchanged logic)
// ---------------------------------------------------------------------------

// parseCSTag splits a cs struct tag value into the column name and remaining directives.
// For example, "email,unique(downcase),match" returns ("email", ["unique(downcase)", "match"]).
func parseCSTag(tag string) (columnName string, directives []string) {
	parts := splitTagParts(tag)
	if len(parts) == 0 {
		return "", nil
	}
	return parts[0], parts[1:]
}

// splitTagParts splits a cs tag value by commas, respecting parenthesized groups.
// For example, "email,match(k=8,m=1024),ore" splits into ["email", "match(k=8,m=1024)", "ore"].
func splitTagParts(tag string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(tag); i++ {
		switch tag[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, tag[start:i])
				start = i + 1
			}
		}
	}
	if start < len(tag) {
		parts = append(parts, tag[start:])
	}
	return parts
}

// parseColumn builds a Column from the directives portion of a cs tag and the Go field type.
func parseColumn(directives []string, fieldType reflect.Type) Column {
	var castAs *CastAs
	var indexes Indexes
	hasIndex := false
	autoJson := false

	for _, d := range directives {
		name, params := extractParams(d)

		switch name {
		case "cast":
			ca := CastAs(params)
			castAs = &ca
		case "unique":
			hasIndex = true
			indexes.UniqueIndex = parseUniqueOpts(params)
		case "match":
			hasIndex = true
			indexes.MatchIndex = parseMatchOpts(params)
		case "ore":
			hasIndex = true
			indexes.OreIndex = &OreIndexOpts{}
		case "ste_vec":
			hasIndex = true
			autoJson = true
			indexes.SteVecIndex = parseSteVecOpts(params)
		}
	}

	// Determine cast type.
	if castAs == nil {
		if autoJson {
			ca := CastAsJSON
			castAs = &ca
		} else {
			ca := inferCastAs(fieldType)
			castAs = &ca
		}
	}

	col := Column{
		CastAs: castAs,
	}
	if hasIndex {
		col.Indexes = &indexes
	}
	return col
}

// parseMatchOpts parses the parameters string for a match index directive.
// An empty params string returns the default match configuration.
func parseMatchOpts(params string) *MatchIndexOpts {
	// Defaults matching the TypeScript SDK.
	tokenizerKind := "ngram"
	tokenLength := 3
	k := 6
	m := 2048
	includeOriginal := true

	if params != "" {
		kvs := parseKeyValues(params)
		for key, val := range kvs {
			switch key {
			case "tokenizer":
				tokenizerKind = val
			case "token_length":
				if n, err := strconv.Atoi(val); err == nil {
					tokenLength = n
				}
			case "k":
				if n, err := strconv.Atoi(val); err == nil {
					k = n
				}
			case "m":
				if n, err := strconv.Atoi(val); err == nil {
					m = n
				}
			case "include_original":
				if b, err := strconv.ParseBool(val); err == nil {
					includeOriginal = b
				}
			}
		}
	}

	opts := &MatchIndexOpts{
		Tokenizer: &Tokenizer{
			Kind: tokenizerKind,
		},
		TokenFilters:    []TokenFilter{{Kind: "downcase"}},
		K:               &k,
		M:               &m,
		IncludeOriginal: &includeOriginal,
	}

	// Only set token_length for ngram tokenizer.
	if tokenizerKind == "ngram" {
		opts.Tokenizer.TokenLength = &tokenLength
	}

	return opts
}

// parseUniqueOpts parses the parameters string for a unique index directive.
func parseUniqueOpts(params string) *UniqueIndexOpts {
	opts := &UniqueIndexOpts{}
	if params == "" {
		return opts
	}

	// The params can be a simple keyword like "downcase" or key=value pairs.
	if params == "downcase" {
		opts.TokenFilters = []TokenFilter{{Kind: "downcase"}}
		return opts
	}

	// Support key=value form as well.
	kvs := parseKeyValues(params)
	for key, val := range kvs {
		if key == "token_filter" && val == "downcase" {
			opts.TokenFilters = []TokenFilter{{Kind: "downcase"}}
		}
	}

	return opts
}

// parseSteVecOpts parses the parameters string for a ste_vec index directive.
func parseSteVecOpts(params string) *SteVecIndexOpts {
	opts := &SteVecIndexOpts{}
	if params == "" {
		return opts
	}

	kvs := parseKeyValues(params)
	for key, val := range kvs {
		switch key {
		case "prefix":
			opts.Prefix = val
		}
	}

	return opts
}

// timeType is the reflect.Type of time.Time, used to infer the timestamp cast.
var timeType = reflect.TypeOf(time.Time{})

// inferCastAs determines the CastAs value from a Go reflect.Type. The result is
// a public CastAs constant; it is normalized to its canonical wire name when the
// encryption config is built.
func inferCastAs(fieldType reflect.Type) CastAs {
	// Dereference pointers.
	for fieldType.Kind() == reflect.Ptr {
		fieldType = fieldType.Elem()
	}

	// time.Time maps to a timestamp column regardless of its struct kind.
	if fieldType == timeType {
		return CastAsTimestamp
	}

	switch fieldType.Kind() {
	case reflect.String:
		return CastAsText
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return CastAsBigInt
	case reflect.Float32, reflect.Float64:
		return CastAsFloat
	case reflect.Bool:
		return CastAsBoolean
	default:
		// Maps, structs, interfaces, slices, arrays, etc.
		return CastAsJSON
	}
}

// extractParams splits a directive like "match(k=8,m=1024)" into ("match", "k=8,m=1024")
// and "ore" into ("ore", ""). For "cast=number", it returns ("cast", "number").
func extractParams(directive string) (name string, params string) {
	// Handle cast=<type> as a special case.
	if strings.HasPrefix(directive, "cast=") {
		return "cast", directive[5:]
	}

	// Handle directives with parenthesized parameters.
	idx := strings.IndexByte(directive, '(')
	if idx < 0 {
		return directive, ""
	}

	name = directive[:idx]
	// Strip the closing paren.
	params = directive[idx+1:]
	if len(params) > 0 && params[len(params)-1] == ')' {
		params = params[:len(params)-1]
	}
	return name, params
}

// parseKeyValues parses a string like "k=8,m=1024,tokenizer=ngram" into a map.
func parseKeyValues(s string) map[string]string {
	result := make(map[string]string)
	pairs := strings.Split(s, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eqIdx := strings.IndexByte(pair, '=')
		if eqIdx < 0 {
			// Bare keyword, store as key with empty value.
			result[pair] = ""
			continue
		}
		result[pair[:eqIdx]] = pair[eqIdx+1:]
	}
	return result
}
