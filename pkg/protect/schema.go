package protect

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// TableDef holds a parsed table schema ready for building an EncryptConfig.
type TableDef struct {
	Name    string
	Columns map[string]Column
}

// TableSchema creates a table schema definition from a struct type.
// It parses the `cs` struct tags to determine column names, cast types, and indexes.
// The model parameter can be a struct value or a pointer to a struct.
// TableSchema panics if model is not a struct or pointer to struct, since this
// indicates a programming error that should be caught during initialization.
func TableSchema(tableName string, model interface{}) *TableDef {
	typ := reflect.TypeOf(model)
	if typ == nil {
		panic("protect.TableSchema: model must not be nil")
	}
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		panic(fmt.Sprintf("protect.TableSchema: model must be a struct, got %s", typ.Kind()))
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
		Name:    tableName,
		Columns: columns,
	}
}

// BuildEncryptConfig creates an EncryptConfig from one or more table schema definitions.
func BuildEncryptConfig(tables ...*TableDef) EncryptConfig {
	tbls := make(Tables, len(tables))
	for _, td := range tables {
		tbl := make(Table, len(td.Columns))
		for colName, col := range td.Columns {
			tbl[colName] = col
		}
		tbls[td.Name] = tbl
	}
	return EncryptConfig{
		Version: 1,
		Tables:  tbls,
	}
}

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
			ca := CastAsJson
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

// inferCastAs determines the CastAs value from a Go reflect.Type.
func inferCastAs(fieldType reflect.Type) CastAs {
	// Dereference pointers.
	for fieldType.Kind() == reflect.Ptr {
		fieldType = fieldType.Elem()
	}

	switch fieldType.Kind() {
	case reflect.String:
		return CastAsString
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return CastAsNumber
	case reflect.Float32, reflect.Float64:
		return CastAsNumber
	case reflect.Bool:
		return CastAsBoolean
	default:
		// Maps, structs, interfaces, slices, arrays, etc.
		return CastAsJson
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
