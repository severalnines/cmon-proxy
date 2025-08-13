package main

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/severalnines/cmon-proxy/config"
)

// applyConfigParams applies arbitrary configuration parameters using reflection.
// Supports both flat and nested parameters using dot notation (e.g., "web_server.security.frame_deny=true").
func applyConfigParams(cfg *config.Config, params []string) error {
	if len(params) == 0 {
		return nil
	}

	for _, param := range params {
		// Skip empty entries defensively
		param = strings.TrimSpace(param)
		if param == "" {
			continue
		}

		// Split into key=value at the first '='
		key, value, found := strings.Cut(param, "=")
		if !found {
			return fmt.Errorf("invalid parameter format: %q (expected key=value)", param)
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			return fmt.Errorf("invalid parameter: empty key in %q", param)
		}

		// If value is quoted (single or double), unquote it to support spaces, commas, etc.
		if unquoted, ok := unquoteIfQuoted(value); ok {
			value = unquoted
		}

		// Normalize common boolean synonyms without changing existing semantics
		// yes/on -> true, no/off -> false. Other values remain intact.
		value = normalizeBooleanSynonyms(value)

		if err := setNestedFieldValue(reflect.ValueOf(cfg), key, value); err != nil {
			return fmt.Errorf("error setting %s: %w", key, err)
		}

		fmt.Printf("Successfully set %s = %s\n", key, value)
	}

	return nil
}

// unquoteIfQuoted removes surrounding matching quotes (' or ") and unescapes content.
// Returns the unquoted string and true when unquoting was applied, otherwise the
// original string and false.
func unquoteIfQuoted(s string) (string, bool) {
	if len(s) < 2 {
		return s, false
	}
	first := s[0]
	last := s[len(s)-1]
	if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
		// Use strconv.Unquote to handle escape sequences
		if unq, err := strconv.Unquote(s); err == nil {
			return unq, true
		}
	}
	return s, false
}

// normalizeBooleanSynonyms converts common boolean aliases to Go-friendly values.
// It does not change values outside of the handled set to avoid altering semantics.
func normalizeBooleanSynonyms(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yes", "on":
		return "true"
	case "no", "off":
		return "false"
	default:
		return s
	}
}

// setNestedFieldValue navigates through nested struct fields using dot notation and sets the final field value.
// It requires a pointer to a struct as the initial value.
func setNestedFieldValue(structPtr reflect.Value, key string, value string) error {
	if structPtr.Kind() != reflect.Ptr || structPtr.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("internal error: initial value must be a pointer to a struct")
	}

	currentValue := structPtr.Elem()
	keyParts := strings.Split(key, ".")

	for i, part := range keyParts {
		currentValue = reflect.Indirect(currentValue)
		if currentValue.Kind() != reflect.Struct {
			return fmt.Errorf("field %q is not a struct, cannot navigate further", part)
		}

		field, found := findFieldByYamlTag(currentValue, part)
		if !found {
			return fmt.Errorf("field with yaml tag %q not found", part)
		}

		if i == len(keyParts)-1 {
			return setFieldValue(field, value, part)
		}

		currentValue = field
	}

	return nil
}

// findFieldByYamlTag finds an exported field in a struct by its yaml tag name.
func findFieldByYamlTag(structValue reflect.Value, yamlTag string) (reflect.Value, bool) {
	structType := structValue.Type()

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		fieldValue := structValue.Field(i)

		if !fieldValue.CanSet() {
			continue
		}

		tag, ok := field.Tag.Lookup("yaml")
		if !ok {
			continue
		}

		tagName, _, _ := strings.Cut(tag, ",")
		if tagName == yamlTag {
			return fieldValue, true
		}
	}

	return reflect.Value{}, false
}

// setFieldValue sets a field's value, handling various types and performing necessary conversions and checks.
func setFieldValue(field reflect.Value, value, fieldName string) error {
	if !field.CanSet() {
		return fmt.Errorf("cannot set field %s", fieldName)
	}

	// If the field is a pointer, initialize it if nil, and then operate on the underlying element.
	if field.Kind() == reflect.Ptr {
		if field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}
		field = field.Elem()
	}

	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Bool:
		boolVal, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean value for %s: %q (use true/false)", fieldName, value)
		}
		field.SetBool(boolVal)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		intVal, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid integer value for %s: %q", fieldName, value)
		}
		if field.OverflowInt(intVal) {
			return fmt.Errorf("integer value %q overflows field %s", value, fieldName)
		}
		field.SetInt(intVal)
	case reflect.Slice:
		if field.Type().Elem().Kind() == reflect.String {
			values := strings.Split(value, ",")
			trimmedValues := make([]string, len(values))
			for i, v := range values {
				trimmedValues[i] = strings.TrimSpace(v)
			}
			field.Set(reflect.ValueOf(trimmedValues))
		} else {
			return fmt.Errorf("unsupported slice type for field %s", fieldName)
		}
	default:
		return fmt.Errorf("unsupported field type %s for field %s", field.Kind(), fieldName)
	}

	return nil
}
