package protect

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"unicode"
)

// modelField holds the metadata extracted from a single struct field with a `cs` tag.
type modelField struct {
	// Index is the struct field index used with reflect.Value.Field().
	Index int
	// Column is the encryption column name from the `cs` struct tag.
	Column string
	// MapKey is the key used in the output map (JSON tag name or snake_case field name).
	MapKey string
}

// modelInfo holds the pre-parsed metadata for a struct type, separating encrypted
// fields (those with a `cs` tag) from plain fields.
type modelInfo struct {
	// EncryptedFields are fields with a valid `cs:"column_name"` tag.
	EncryptedFields []modelField
	// PlainFields are fields without a `cs` tag (or with `cs:"-"`).
	PlainFields []modelField
}

// analyzeStruct inspects a struct type and returns its modelInfo.
// It returns an error if typ is not a struct type.
func analyzeStruct(typ reflect.Type) (*modelInfo, error) {
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected a struct type, got %s", typ.Kind())
	}

	info := &modelInfo{}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)

		// Skip unexported fields.
		if !field.IsExported() {
			continue
		}

		mapKey := fieldMapKey(field)
		csTag, hasCS := field.Tag.Lookup("cs")

		if hasCS && csTag != "-" && csTag != "" {
			columnName := strings.Split(csTag, ",")[0]
			if columnName != "" && columnName != "-" {
				info.EncryptedFields = append(info.EncryptedFields, modelField{
					Index:  i,
					Column: columnName,
					MapKey: mapKey,
				})
			} else {
				info.PlainFields = append(info.PlainFields, modelField{
					Index:  i,
					MapKey: mapKey,
				})
			}
		} else {
			info.PlainFields = append(info.PlainFields, modelField{
				Index:  i,
				MapKey: mapKey,
			})
		}
	}

	return info, nil
}

// fieldMapKey returns the map key for a struct field. It uses the JSON tag name
// if present, otherwise converts the field name to snake_case.
func fieldMapKey(f reflect.StructField) string {
	if jsonTag, ok := f.Tag.Lookup("json"); ok {
		name := strings.Split(jsonTag, ",")[0]
		if name != "" && name != "-" {
			return name
		}
	}
	return toSnakeCase(f.Name)
}

// toSnakeCase converts a CamelCase string to snake_case.
func toSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				result.WriteByte('_')
			}
			result.WriteRune(unicode.ToLower(r))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// fieldPlaintext extracts the plaintext value from a struct field, handling pointer
// types by dereferencing them. It returns the value and whether the field is nil.
func fieldPlaintext(v reflect.Value) (any, bool) {
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil, true
		}
		v = v.Elem()
	}
	return v.Interface(), false
}

// EncryptModel encrypts the tagged fields of a struct and returns a map with
// encrypted values for `cs`-tagged fields and original values for all other fields.
//
// The model parameter must be a struct (or pointer to struct). The schema parameter
// identifies the table and columns in the encryption config. Each field with a
// `cs:"column_name"` tag is encrypted using [Client.Encrypt]. Fields without
// the tag are copied as-is.
func (c *Client) EncryptModel(ctx context.Context, schema *TableDef, model any) (map[string]any, error) {
	v := reflect.ValueOf(model)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil, fmt.Errorf("model must not be nil")
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("model must be a struct, got %s", v.Kind())
	}

	info, err := analyzeStruct(v.Type())
	if err != nil {
		return nil, fmt.Errorf("analyzing model: %w", err)
	}

	result := make(map[string]any, len(info.EncryptedFields)+len(info.PlainFields))

	// Copy plain fields.
	for _, pf := range info.PlainFields {
		result[pf.MapKey] = v.Field(pf.Index).Interface()
	}

	// Encrypt tagged fields.
	for _, ef := range info.EncryptedFields {
		plaintext, isNil := fieldPlaintext(v.Field(ef.Index))
		if isNil {
			result[ef.MapKey] = nil
			continue
		}

		encrypted, err := c.Encrypt(ctx, schema.Column(ef.Column), plaintext)
		if err != nil {
			return nil, fmt.Errorf("encrypting field %q (column %q): %w", ef.MapKey, ef.Column, err)
		}
		result[ef.MapKey] = encrypted
	}

	return result, nil
}

// DecryptModel decrypts the encrypted fields in a map and populates the destination struct.
//
// The dest parameter must be a pointer to a struct. For each field in the struct with
// a `cs:"column_name"` tag, the corresponding map value is treated as an [Encrypted]
// payload, decrypted using [Client.Decrypt], and the resulting plaintext is set on the
// field. Non-tagged fields are set directly from the map.
func (c *Client) DecryptModel(ctx context.Context, schema *TableDef, data map[string]any, dest any) error {
	v := reflect.ValueOf(dest)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return fmt.Errorf("dest must be a non-nil pointer to a struct")
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("dest must be a pointer to a struct, got pointer to %s", v.Kind())
	}

	info, err := analyzeStruct(v.Type())
	if err != nil {
		return fmt.Errorf("analyzing dest: %w", err)
	}

	// Set plain fields.
	for _, pf := range info.PlainFields {
		rawVal, exists := data[pf.MapKey]
		if !exists {
			continue
		}
		setFieldValue(v.Field(pf.Index), rawVal)
	}

	// Decrypt tagged fields.
	for _, ef := range info.EncryptedFields {
		rawVal, exists := data[ef.MapKey]
		if !exists || rawVal == nil {
			continue
		}

		encrypted, err := toEncrypted(rawVal)
		if err != nil {
			return fmt.Errorf("converting field %q to Encrypted: %w", ef.MapKey, err)
		}

		plaintext, err := c.Decrypt(ctx, encrypted)
		if err != nil {
			return fmt.Errorf("decrypting field %q (column %q): %w", ef.MapKey, ef.Column, err)
		}

		setFieldValue(v.Field(ef.Index), plaintext)
	}

	return nil
}

// BulkEncryptModels encrypts multiple structs using a single bulk encryption call.
//
// The models parameter must be a slice of structs (or pointer to slice). Each struct's
// `cs`-tagged fields are collected into a single call to [Client.EncryptBulk], which is
// significantly more efficient than calling [Client.EncryptModel] for each struct individually.
func (c *Client) BulkEncryptModels(ctx context.Context, schema *TableDef, models any) ([]map[string]any, error) {
	sv := reflect.ValueOf(models)
	if sv.Kind() == reflect.Ptr {
		if sv.IsNil() {
			return nil, fmt.Errorf("models must not be nil")
		}
		sv = sv.Elem()
	}
	if sv.Kind() != reflect.Slice {
		return nil, fmt.Errorf("models must be a slice, got %s", sv.Kind())
	}
	if sv.Len() == 0 {
		return []map[string]any{}, nil
	}

	elemType := sv.Type().Elem()
	if elemType.Kind() == reflect.Ptr {
		elemType = elemType.Elem()
	}

	info, err := analyzeStruct(elemType)
	if err != nil {
		return nil, fmt.Errorf("analyzing model type: %w", err)
	}

	numModels := sv.Len()
	numEncFields := len(info.EncryptedFields)

	// Build bulk plaintext payloads and result maps in one pass.
	results := make([]map[string]any, numModels)
	var payloads []PlaintextItem
	// Track which payloads map to which result slot.
	type payloadPos struct {
		modelIdx int
		mapKey   string
	}
	var positions []payloadPos

	for i := 0; i < numModels; i++ {
		elem := sv.Index(i)
		if elem.Kind() == reflect.Ptr {
			if elem.IsNil() {
				results[i] = nil
				continue
			}
			elem = elem.Elem()
		}

		result := make(map[string]any, numEncFields+len(info.PlainFields))

		// Copy plain fields.
		for _, pf := range info.PlainFields {
			result[pf.MapKey] = elem.Field(pf.Index).Interface()
		}

		// Collect encrypted fields.
		for _, ef := range info.EncryptedFields {
			plaintext, isNil := fieldPlaintext(elem.Field(ef.Index))
			if isNil {
				result[ef.MapKey] = nil
				continue
			}
			payloads = append(payloads, PlaintextItem{
				Plaintext: plaintext,
				Column:    schema.Column(ef.Column),
			})
			positions = append(positions, payloadPos{modelIdx: i, mapKey: ef.MapKey})
		}

		results[i] = result
	}

	if len(payloads) == 0 {
		return results, nil
	}

	encrypted, err := c.EncryptBulk(ctx, payloads)
	if err != nil {
		return nil, fmt.Errorf("bulk encrypting models: %w", err)
	}

	if len(encrypted) != len(positions) {
		return nil, fmt.Errorf("bulk encrypt returned %d results, expected %d", len(encrypted), len(positions))
	}

	// Distribute encrypted values back.
	for i, pos := range positions {
		enc := encrypted[i]
		results[pos.modelIdx][pos.mapKey] = &enc
	}

	return results, nil
}

// BulkDecryptModels decrypts multiple encrypted maps and populates a slice of structs.
//
// The dest parameter must be a pointer to a slice of structs. All encrypted values
// across the maps are collected into a single call to [Client.DecryptBulk], which is
// significantly more efficient than calling [Client.DecryptModel] for each map individually.
func (c *Client) BulkDecryptModels(ctx context.Context, schema *TableDef, data []map[string]any, dest any) error {
	dv := reflect.ValueOf(dest)
	if dv.Kind() != reflect.Ptr || dv.IsNil() {
		return fmt.Errorf("dest must be a non-nil pointer to a slice of structs")
	}
	sliceVal := dv.Elem()
	if sliceVal.Kind() != reflect.Slice {
		return fmt.Errorf("dest must be a pointer to a slice, got pointer to %s", sliceVal.Kind())
	}

	elemType := sliceVal.Type().Elem()
	if elemType.Kind() == reflect.Ptr {
		elemType = elemType.Elem()
	}

	info, err := analyzeStruct(elemType)
	if err != nil {
		return fmt.Errorf("analyzing dest element type: %w", err)
	}

	numMaps := len(data)

	// Collect all ciphertexts for bulk decryption.
	type decryptPos struct {
		mapIdx   int
		fieldIdx int // index into info.EncryptedFields
	}
	var ciphertexts []*Encrypted
	var positions []decryptPos

	for i, m := range data {
		for j, ef := range info.EncryptedFields {
			rawVal, exists := m[ef.MapKey]
			if !exists || rawVal == nil {
				continue
			}
			encrypted, err := toEncrypted(rawVal)
			if err != nil {
				return fmt.Errorf("converting field %q in map[%d] to Encrypted: %w", ef.MapKey, i, err)
			}
			ciphertexts = append(ciphertexts, encrypted)
			positions = append(positions, decryptPos{mapIdx: i, fieldIdx: j})
		}
	}

	// Allocate the result slice.
	resultSlice := reflect.MakeSlice(sliceVal.Type(), numMaps, numMaps)

	// Set plain fields.
	for i, m := range data {
		elem := resultSlice.Index(i)
		if elem.Kind() == reflect.Ptr {
			elem.Set(reflect.New(elemType))
			elem = elem.Elem()
		}
		for _, pf := range info.PlainFields {
			rawVal, exists := m[pf.MapKey]
			if !exists {
				continue
			}
			setFieldValue(elem.Field(pf.Index), rawVal)
		}
	}

	// Bulk decrypt if there are any ciphertexts.
	if len(ciphertexts) > 0 {
		plaintexts, err := c.DecryptBulk(ctx, ciphertexts)
		if err != nil {
			return fmt.Errorf("bulk decrypting models: %w", err)
		}

		if len(plaintexts) != len(positions) {
			return fmt.Errorf("bulk decrypt returned %d results, expected %d", len(plaintexts), len(positions))
		}

		for i, pos := range positions {
			elem := resultSlice.Index(pos.mapIdx)
			if elem.Kind() == reflect.Ptr {
				elem = elem.Elem()
			}
			ef := info.EncryptedFields[pos.fieldIdx]
			setFieldValue(elem.Field(ef.Index), plaintexts[i])
		}
	}

	sliceVal.Set(resultSlice)
	return nil
}

// toEncrypted converts a raw value (typically a map from JSON deserialization) into
// an *Encrypted struct by marshaling to JSON and unmarshaling back.
func toEncrypted(val any) (*Encrypted, error) {
	switch v := val.(type) {
	case *Encrypted:
		return v, nil
	case Encrypted:
		return &v, nil
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshaling value to JSON: %w", err)
		}
		var enc Encrypted
		if err := json.Unmarshal(data, &enc); err != nil {
			return nil, fmt.Errorf("unmarshaling value to Encrypted: %w", err)
		}
		return &enc, nil
	}
}

// setFieldValue sets a struct field from an arbitrary value, handling type coercion
// for common cases (e.g., JSON numbers to int fields, strings to string fields).
func setFieldValue(field reflect.Value, val any) {
	if val == nil {
		return
	}

	fieldType := field.Type()
	valReflect := reflect.ValueOf(val)

	// Handle pointer fields.
	if fieldType.Kind() == reflect.Ptr {
		elemType := fieldType.Elem()
		ptr := reflect.New(elemType)
		setFieldValue(ptr.Elem(), val)
		field.Set(ptr)
		return
	}

	// Direct assignment if types are compatible.
	if valReflect.Type().AssignableTo(fieldType) {
		field.Set(valReflect)
		return
	}

	// Handle type coercion for JSON-deserialized values.
	switch fieldType.Kind() {
	case reflect.String:
		if s, ok := val.(string); ok {
			field.SetString(s)
		} else {
			field.SetString(fmt.Sprintf("%v", val))
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		switch n := val.(type) {
		case float64:
			field.SetInt(int64(n))
		case float32:
			field.SetInt(int64(n))
		case int:
			field.SetInt(int64(n))
		case int64:
			field.SetInt(n)
		case json.Number:
			if i, err := n.Int64(); err == nil {
				field.SetInt(i)
			}
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		switch n := val.(type) {
		case float64:
			field.SetUint(uint64(n))
		case int:
			field.SetUint(uint64(n))
		case uint64:
			field.SetUint(n)
		}
	case reflect.Float32, reflect.Float64:
		switch n := val.(type) {
		case float64:
			field.SetFloat(n)
		case float32:
			field.SetFloat(float64(n))
		case int:
			field.SetFloat(float64(n))
		case json.Number:
			if f, err := n.Float64(); err == nil {
				field.SetFloat(f)
			}
		}
	case reflect.Bool:
		if b, ok := val.(bool); ok {
			field.SetBool(b)
		}
	}
}
