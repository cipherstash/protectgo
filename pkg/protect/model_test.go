package protect

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

// --- Test structs used across multiple tests ---

type userModel struct {
	ID    int    `json:"id"`
	Email string `json:"email" cs:"email"`
	Name  string `json:"name" cs:"name"`
	Role  string `json:"role"`
}

type pointerFieldModel struct {
	ID    int     `json:"id"`
	Email *string `json:"email" cs:"email"`
	Name  *string `json:"name" cs:"name"`
}

type noCSTagModel struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type skipFieldModel struct {
	ID    int    `json:"id"`
	Email string `json:"email" cs:"email"`
	Skip  string `json:"skip" cs:"-"`
}

type noJSONTagModel struct {
	ID        int
	FirstName string `cs:"first_name"`
	LastName  string
}

type mixedModel struct {
	ID      int     `json:"id"`
	Email   string  `json:"email" cs:"email"`
	Name    *string `json:"name" cs:"name"`
	Active  bool    `json:"active"`
	Balance float64 `json:"balance"`
}

type emptyModel struct{}

type unexportedFieldModel struct {
	ID    int    `json:"id"`
	Email string `json:"email" cs:"email"`
	// unexported fields should be skipped
	secret string //nolint:unused
}

// --- analyzeStruct tests ---

func TestAnalyzeStruct(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		typ              reflect.Type
		wantEncrypted    int
		wantPlain        int
		wantErr          bool
		encryptedColumns []string
		encryptedMapKeys []string
		plainMapKeys     []string
	}{
		{
			name:             "basic user model",
			typ:              reflect.TypeOf(userModel{}),
			wantEncrypted:    2,
			wantPlain:        2,
			encryptedColumns: []string{"email", "name"},
			encryptedMapKeys: []string{"email", "name"},
			plainMapKeys:     []string{"id", "role"},
		},
		{
			name:             "pointer fields",
			typ:              reflect.TypeOf(pointerFieldModel{}),
			wantEncrypted:    2,
			wantPlain:        1,
			encryptedColumns: []string{"email", "name"},
			plainMapKeys:     []string{"id"},
		},
		{
			name:          "no cs tags",
			typ:           reflect.TypeOf(noCSTagModel{}),
			wantEncrypted: 0,
			wantPlain:     2,
			plainMapKeys:  []string{"id", "name"},
		},
		{
			name:             "cs skip tag",
			typ:              reflect.TypeOf(skipFieldModel{}),
			wantEncrypted:    1,
			wantPlain:        2,
			encryptedColumns: []string{"email"},
			plainMapKeys:     []string{"id", "skip"},
		},
		{
			name:          "empty struct",
			typ:           reflect.TypeOf(emptyModel{}),
			wantEncrypted: 0,
			wantPlain:     0,
		},
		{
			name:             "pointer to struct",
			typ:              reflect.TypeOf(&userModel{}),
			wantEncrypted:    2,
			wantPlain:        2,
			encryptedColumns: []string{"email", "name"},
		},
		{
			name:             "unexported fields skipped",
			typ:              reflect.TypeOf(unexportedFieldModel{}),
			wantEncrypted:    1,
			wantPlain:        1,
			encryptedColumns: []string{"email"},
			plainMapKeys:     []string{"id"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			info, err := analyzeStruct(tc.typ)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(info.EncryptedFields) != tc.wantEncrypted {
				t.Errorf("encrypted fields: got %d, want %d", len(info.EncryptedFields), tc.wantEncrypted)
			}
			if len(info.PlainFields) != tc.wantPlain {
				t.Errorf("plain fields: got %d, want %d", len(info.PlainFields), tc.wantPlain)
			}

			for i, col := range tc.encryptedColumns {
				if i < len(info.EncryptedFields) && info.EncryptedFields[i].Column != col {
					t.Errorf("encrypted field %d: column got %q, want %q", i, info.EncryptedFields[i].Column, col)
				}
			}
			for i, key := range tc.encryptedMapKeys {
				if i < len(info.EncryptedFields) && info.EncryptedFields[i].MapKey != key {
					t.Errorf("encrypted field %d: map key got %q, want %q", i, info.EncryptedFields[i].MapKey, key)
				}
			}
			for i, key := range tc.plainMapKeys {
				if i < len(info.PlainFields) && info.PlainFields[i].MapKey != key {
					t.Errorf("plain field %d: map key got %q, want %q", i, info.PlainFields[i].MapKey, key)
				}
			}
		})
	}
}

func TestAnalyzeStructRejectsNonStruct(t *testing.T) {
	t.Parallel()

	_, err := analyzeStruct(reflect.TypeOf("not a struct"))
	if err == nil {
		t.Fatal("expected error for non-struct type")
	}

	_, err = analyzeStruct(reflect.TypeOf(42))
	if err == nil {
		t.Fatal("expected error for int type")
	}

	_, err = analyzeStruct(reflect.TypeOf([]string{}))
	if err == nil {
		t.Fatal("expected error for slice type")
	}
}

// --- fieldMapKey tests ---

func TestFieldMapKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		typ      reflect.Type
		fieldIdx int
		want     string
	}{
		{
			name:     "json tag present",
			typ:      reflect.TypeOf(userModel{}),
			fieldIdx: 0, // ID field with json:"id"
			want:     "id",
		},
		{
			name:     "no json tag uses snake_case",
			typ:      reflect.TypeOf(noJSONTagModel{}),
			fieldIdx: 0, // ID field with no json tag
			want:     "i_d",
		},
		{
			name:     "camel case to snake_case",
			typ:      reflect.TypeOf(noJSONTagModel{}),
			fieldIdx: 1, // FirstName field with cs but no json tag
			want:     "first_name",
		},
		{
			name:     "simple lowercase",
			typ:      reflect.TypeOf(noJSONTagModel{}),
			fieldIdx: 2, // LastName field
			want:     "last_name",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			field := tc.typ.Field(tc.fieldIdx)
			got := fieldMapKey(field)
			if got != tc.want {
				t.Errorf("fieldMapKey(%s) = %q, want %q", field.Name, got, tc.want)
			}
		})
	}
}

// --- toSnakeCase tests ---

func TestToSnakeCase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"ID", "i_d"},
		{"FirstName", "first_name"},
		{"lastName", "last_name"},
		{"email", "email"},
		{"HTMLParser", "h_t_m_l_parser"},
		{"A", "a"},
		{"", ""},
		{"alreadylower", "alreadylower"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			got := toSnakeCase(tc.input)
			if got != tc.want {
				t.Errorf("toSnakeCase(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// --- fieldPlaintext tests ---

func TestFieldPlaintext(t *testing.T) {
	t.Parallel()

	t.Run("direct string value", func(t *testing.T) {
		t.Parallel()
		v := reflect.ValueOf("hello")
		val, isNil := fieldPlaintext(v)
		if isNil {
			t.Fatal("expected non-nil")
		}
		if val != "hello" {
			t.Errorf("got %v, want %q", val, "hello")
		}
	})

	t.Run("direct int value", func(t *testing.T) {
		t.Parallel()
		v := reflect.ValueOf(42)
		val, isNil := fieldPlaintext(v)
		if isNil {
			t.Fatal("expected non-nil")
		}
		if val != 42 {
			t.Errorf("got %v, want 42", val)
		}
	})

	t.Run("non-nil pointer", func(t *testing.T) {
		t.Parallel()
		s := "world"
		v := reflect.ValueOf(&s)
		val, isNil := fieldPlaintext(v)
		if isNil {
			t.Fatal("expected non-nil")
		}
		if val != "world" {
			t.Errorf("got %v, want %q", val, "world")
		}
	})

	t.Run("nil pointer", func(t *testing.T) {
		t.Parallel()
		var s *string
		v := reflect.ValueOf(s)
		_, isNil := fieldPlaintext(v)
		if !isNil {
			t.Fatal("expected nil")
		}
	})

	t.Run("bool value", func(t *testing.T) {
		t.Parallel()
		v := reflect.ValueOf(true)
		val, isNil := fieldPlaintext(v)
		if isNil {
			t.Fatal("expected non-nil")
		}
		if val != true {
			t.Errorf("got %v, want true", val)
		}
	})

	t.Run("float value", func(t *testing.T) {
		t.Parallel()
		v := reflect.ValueOf(3.14)
		val, isNil := fieldPlaintext(v)
		if isNil {
			t.Fatal("expected non-nil")
		}
		if val != 3.14 {
			t.Errorf("got %v, want 3.14", val)
		}
	})
}

// --- setFieldValue tests ---

func TestSetFieldValue(t *testing.T) {
	t.Parallel()

	t.Run("string to string", func(t *testing.T) {
		t.Parallel()
		var s string
		v := reflect.ValueOf(&s).Elem()
		setFieldValue(v, "hello")
		if s != "hello" {
			t.Errorf("got %q, want %q", s, "hello")
		}
	})

	t.Run("float64 to int", func(t *testing.T) {
		t.Parallel()
		var i int
		v := reflect.ValueOf(&i).Elem()
		setFieldValue(v, float64(42))
		if i != 42 {
			t.Errorf("got %d, want 42", i)
		}
	})

	t.Run("float64 to float64", func(t *testing.T) {
		t.Parallel()
		var f float64
		v := reflect.ValueOf(&f).Elem()
		setFieldValue(v, float64(3.14))
		if f != 3.14 {
			t.Errorf("got %f, want 3.14", f)
		}
	})

	t.Run("bool to bool", func(t *testing.T) {
		t.Parallel()
		var b bool
		v := reflect.ValueOf(&b).Elem()
		setFieldValue(v, true)
		if !b {
			t.Error("got false, want true")
		}
	})

	t.Run("string to pointer string", func(t *testing.T) {
		t.Parallel()
		var s *string
		v := reflect.ValueOf(&s).Elem()
		setFieldValue(v, "world")
		if s == nil {
			t.Fatal("got nil pointer")
		}
		if *s != "world" {
			t.Errorf("got %q, want %q", *s, "world")
		}
	})

	t.Run("nil value is no-op", func(t *testing.T) {
		t.Parallel()
		s := "original"
		v := reflect.ValueOf(&s).Elem()
		setFieldValue(v, nil)
		if s != "original" {
			t.Errorf("got %q, want %q", s, "original")
		}
	})

	t.Run("int to int", func(t *testing.T) {
		t.Parallel()
		var i int
		v := reflect.ValueOf(&i).Elem()
		setFieldValue(v, int(7))
		if i != 7 {
			t.Errorf("got %d, want 7", i)
		}
	})

	t.Run("float64 to uint", func(t *testing.T) {
		t.Parallel()
		var u uint
		v := reflect.ValueOf(&u).Elem()
		setFieldValue(v, float64(100))
		if u != 100 {
			t.Errorf("got %d, want 100", u)
		}
	})

	t.Run("non-string to string via format", func(t *testing.T) {
		t.Parallel()
		var s string
		v := reflect.ValueOf(&s).Elem()
		setFieldValue(v, 42)
		if s != "42" {
			t.Errorf("got %q, want %q", s, "42")
		}
	})
}

func TestSetFieldValueJSONNumber(t *testing.T) {
	t.Parallel()

	t.Run("json.Number to int64 preserves large values", func(t *testing.T) {
		t.Parallel()
		var i int64
		v := reflect.ValueOf(&i).Elem()
		// 9007199254740993 = 2^53 + 1, which would lose precision as float64.
		setFieldValue(v, json.Number("9007199254740993"))
		if i != 9007199254740993 {
			t.Errorf("got %d, want 9007199254740993", i)
		}
	})

	t.Run("json.Number to uint", func(t *testing.T) {
		t.Parallel()
		var u uint64
		v := reflect.ValueOf(&u).Elem()
		setFieldValue(v, json.Number("42"))
		if u != 42 {
			t.Errorf("got %d, want 42", u)
		}
	})

	t.Run("json.Number to float", func(t *testing.T) {
		t.Parallel()
		var f float64
		v := reflect.ValueOf(&f).Elem()
		setFieldValue(v, json.Number("3.5"))
		if f != 3.5 {
			t.Errorf("got %v, want 3.5", f)
		}
	})
}

func TestSetFieldValueTime(t *testing.T) {
	t.Parallel()

	t.Run("RFC3339 string to time.Time", func(t *testing.T) {
		t.Parallel()
		var tm time.Time
		v := reflect.ValueOf(&tm).Elem()
		setFieldValue(v, "2021-03-04T05:06:07Z")
		want := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
		if !tm.Equal(want) {
			t.Errorf("got %v, want %v", tm, want)
		}
	})

	t.Run("date-only string to time.Time", func(t *testing.T) {
		t.Parallel()
		var tm time.Time
		v := reflect.ValueOf(&tm).Elem()
		setFieldValue(v, "2021-03-04")
		want := time.Date(2021, 3, 4, 0, 0, 0, 0, time.UTC)
		if !tm.Equal(want) {
			t.Errorf("got %v, want %v", tm, want)
		}
	})

	t.Run("time.Time value assigns directly", func(t *testing.T) {
		t.Parallel()
		var tm time.Time
		v := reflect.ValueOf(&tm).Elem()
		want := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		setFieldValue(v, want)
		if !tm.Equal(want) {
			t.Errorf("got %v, want %v", tm, want)
		}
	})

	t.Run("pointer to time.Time from string", func(t *testing.T) {
		t.Parallel()
		var tm *time.Time
		v := reflect.ValueOf(&tm).Elem()
		setFieldValue(v, "2021-03-04T05:06:07Z")
		if tm == nil {
			t.Fatal("got nil pointer")
		}
		want := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
		if !tm.Equal(want) {
			t.Errorf("got %v, want %v", *tm, want)
		}
	})
}

func TestParseTime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantOK  bool
		wantVal time.Time
	}{
		{"rfc3339", "2021-03-04T05:06:07Z", true, time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)},
		{"rfc3339 nano", "2021-03-04T05:06:07.5Z", true, time.Date(2021, 3, 4, 5, 6, 7, 500000000, time.UTC)},
		{"date only", "2021-03-04", true, time.Date(2021, 3, 4, 0, 0, 0, 0, time.UTC)},
		{"garbage", "not a time", false, time.Time{}},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseTime(tc.input)
			if ok != tc.wantOK {
				t.Fatalf("ok: got %v, want %v", ok, tc.wantOK)
			}
			if ok && !got.Equal(tc.wantVal) {
				t.Errorf("got %v, want %v", got, tc.wantVal)
			}
		})
	}
}

// --- toEncrypted tests ---

func TestToEncrypted(t *testing.T) {
	t.Parallel()

	t.Run("from *Encrypted", func(t *testing.T) {
		t.Parallel()
		ct := "cipher"
		enc := &Encrypted{
			Identifier: Identifier{Table: "users", Column: "email"},
			Version:    1,
			Ciphertext: &ct,
		}
		result, err := toEncrypted(enc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != enc {
			t.Error("expected same pointer back")
		}
	})

	t.Run("from Encrypted value", func(t *testing.T) {
		t.Parallel()
		ct := "cipher"
		enc := Encrypted{
			Identifier: Identifier{Table: "users", Column: "email"},
			Version:    1,
			Ciphertext: &ct,
		}
		result, err := toEncrypted(enc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if *result.Ciphertext != "cipher" {
			t.Errorf("ciphertext: got %q, want %q", *result.Ciphertext, "cipher")
		}
	})

	t.Run("from map (JSON deserialized)", func(t *testing.T) {
		t.Parallel()
		m := map[string]any{
			"i": map[string]any{
				"t": "users",
				"c": "email",
			},
			"v": float64(1),
			"c": "encrypted-data",
		}
		result, err := toEncrypted(m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Identifier.Table != "users" {
			t.Errorf("table: got %q, want %q", result.Identifier.Table, "users")
		}
		if result.Identifier.Column != "email" {
			t.Errorf("column: got %q, want %q", result.Identifier.Column, "email")
		}
		if result.Ciphertext == nil || *result.Ciphertext != "encrypted-data" {
			t.Errorf("ciphertext: got %v, want %q", result.Ciphertext, "encrypted-data")
		}
	})

	t.Run("from invalid type returns error", func(t *testing.T) {
		t.Parallel()
		_, err := toEncrypted("not-a-map")
		if err == nil {
			t.Fatal("expected error for invalid type")
		}
	})
}

// --- Client closed tests for model methods ---

func TestEncryptModelClientClosed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	c := &Client{} // ptr is nil — simulates a closed client
	schema := &TableDef{name: "users", columns: map[string]Column{}}

	_, err := c.EncryptModel(ctx, schema, userModel{})
	if err == nil {
		t.Fatal("expected error for closed client")
	}
	if !errors.Is(err, ErrClientClosed) {
		t.Errorf("expected ErrClientClosed, got: %v", err)
	}
}

func TestDecryptModelClientClosed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	c := &Client{}
	schema := &TableDef{name: "users", columns: map[string]Column{}}

	err := c.DecryptModel(ctx, schema, map[string]any{"id": 1}, &userModel{})
	if err == nil {
		t.Fatal("expected error for closed client")
	}
	if !errors.Is(err, ErrClientClosed) {
		t.Errorf("expected ErrClientClosed, got: %v", err)
	}
}

func TestBulkEncryptModelsClientClosed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	c := &Client{}
	schema := &TableDef{name: "users", columns: map[string]Column{}}

	_, err := c.BulkEncryptModels(ctx, schema, []userModel{{ID: 1}})
	if err == nil {
		t.Fatal("expected error for closed client")
	}
	if !errors.Is(err, ErrClientClosed) {
		t.Errorf("expected ErrClientClosed, got: %v", err)
	}
}

func TestBulkDecryptModelsClientClosed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	c := &Client{}
	schema := &TableDef{name: "users", columns: map[string]Column{}}

	var users []userModel
	err := c.BulkDecryptModels(ctx, schema, []map[string]any{{"id": 1}}, &users)
	if err == nil {
		t.Fatal("expected error for closed client")
	}
	if !errors.Is(err, ErrClientClosed) {
		t.Errorf("expected ErrClientClosed, got: %v", err)
	}
}

// --- Struct with no encrypted fields ---

func TestAnalyzeStructNoEncryptedFields(t *testing.T) {
	t.Parallel()

	info, err := analyzeStruct(reflect.TypeOf(noCSTagModel{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(info.EncryptedFields) != 0 {
		t.Errorf("expected 0 encrypted fields, got %d", len(info.EncryptedFields))
	}
	if len(info.PlainFields) != 2 {
		t.Errorf("expected 2 plain fields, got %d", len(info.PlainFields))
	}
}

// --- Mixed field types ---

func TestAnalyzeMixedModel(t *testing.T) {
	t.Parallel()

	info, err := analyzeStruct(reflect.TypeOf(mixedModel{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(info.EncryptedFields) != 2 {
		t.Errorf("expected 2 encrypted fields, got %d", len(info.EncryptedFields))
	}
	if len(info.PlainFields) != 3 {
		t.Errorf("expected 3 plain fields (id, active, balance), got %d", len(info.PlainFields))
	}

	expectedColumns := map[string]bool{"email": true, "name": true}
	for _, ef := range info.EncryptedFields {
		if !expectedColumns[ef.Column] {
			t.Errorf("unexpected encrypted column: %q", ef.Column)
		}
	}
}

// --- Test that cs:"-" fields end up as plain fields ---

func TestCSSkipTag(t *testing.T) {
	t.Parallel()

	info, err := analyzeStruct(reflect.TypeOf(skipFieldModel{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(info.EncryptedFields) != 1 {
		t.Errorf("expected 1 encrypted field, got %d", len(info.EncryptedFields))
	}
	if info.EncryptedFields[0].Column != "email" {
		t.Errorf("expected encrypted column %q, got %q", "email", info.EncryptedFields[0].Column)
	}

	if len(info.PlainFields) != 2 {
		t.Errorf("expected 2 plain fields, got %d", len(info.PlainFields))
	}

	plainKeys := make(map[string]bool)
	for _, pf := range info.PlainFields {
		plainKeys[pf.MapKey] = true
	}
	if !plainKeys["id"] {
		t.Error("expected 'id' in plain fields")
	}
	if !plainKeys["skip"] {
		t.Error("expected 'skip' in plain fields")
	}
}

// --- Test JSON tag with options like omitempty ---

type jsonOptsModel struct {
	ID    int    `json:"id,omitempty"`
	Email string `json:"email,omitempty" cs:"email"`
}

func TestJSONTagWithOptions(t *testing.T) {
	t.Parallel()

	info, err := analyzeStruct(reflect.TypeOf(jsonOptsModel{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(info.EncryptedFields) != 1 {
		t.Fatalf("expected 1 encrypted field, got %d", len(info.EncryptedFields))
	}
	if info.EncryptedFields[0].MapKey != "email" {
		t.Errorf("map key: got %q, want %q", info.EncryptedFields[0].MapKey, "email")
	}

	if len(info.PlainFields) != 1 {
		t.Fatalf("expected 1 plain field, got %d", len(info.PlainFields))
	}
	if info.PlainFields[0].MapKey != "id" {
		t.Errorf("map key: got %q, want %q", info.PlainFields[0].MapKey, "id")
	}
}

// --- Test setFieldValue on struct ---

func TestSetFieldValueOnStruct(t *testing.T) {
	t.Parallel()

	t.Run("populate user from map values", func(t *testing.T) {
		t.Parallel()
		var u userModel
		v := reflect.ValueOf(&u).Elem()

		setFieldValue(v.Field(0), float64(1)) // ID
		setFieldValue(v.Field(3), "admin")    // Role

		if u.ID != 1 {
			t.Errorf("ID: got %d, want 1", u.ID)
		}
		if u.Role != "admin" {
			t.Errorf("Role: got %q, want %q", u.Role, "admin")
		}
	})

	t.Run("populate pointer fields", func(t *testing.T) {
		t.Parallel()
		var m pointerFieldModel
		v := reflect.ValueOf(&m).Elem()

		setFieldValue(v.Field(0), float64(2))      // ID
		setFieldValue(v.Field(1), "test@test.com") // Email *string

		if m.ID != 2 {
			t.Errorf("ID: got %d, want 2", m.ID)
		}
		if m.Email == nil {
			t.Fatal("Email: got nil pointer")
		}
		if *m.Email != "test@test.com" {
			t.Errorf("Email: got %q, want %q", *m.Email, "test@test.com")
		}
	})
}

// --- Test empty cs tag is treated as plain field ---

type emptyCSTagModel struct {
	ID    int    `json:"id"`
	Email string `json:"email" cs:""`
}

func TestEmptyCSTag(t *testing.T) {
	t.Parallel()

	info, err := analyzeStruct(reflect.TypeOf(emptyCSTagModel{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(info.EncryptedFields) != 0 {
		t.Errorf("expected 0 encrypted fields for empty cs tag, got %d", len(info.EncryptedFields))
	}
	if len(info.PlainFields) != 2 {
		t.Errorf("expected 2 plain fields, got %d", len(info.PlainFields))
	}
}

// --- Test JSON tag "-" means field falls back to snake_case ---

type jsonSkipModel struct {
	ID     int    `json:"-"`
	Email  string `json:"email" cs:"email"`
	Hidden string `json:"-"`
}

func TestJSONSkipTag(t *testing.T) {
	t.Parallel()

	info, err := analyzeStruct(reflect.TypeOf(jsonSkipModel{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(info.PlainFields) != 2 {
		t.Fatalf("expected 2 plain fields, got %d", len(info.PlainFields))
	}

	if info.PlainFields[0].MapKey != "i_d" {
		t.Errorf("ID map key: got %q, want %q", info.PlainFields[0].MapKey, "i_d")
	}
	if info.PlainFields[1].MapKey != "hidden" {
		t.Errorf("Hidden map key: got %q, want %q", info.PlainFields[1].MapKey, "hidden")
	}
}
