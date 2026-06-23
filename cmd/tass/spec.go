package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	_ "embed"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

//go:embed schemas/manifest.schema.json
var manifestSchemaJSON []byte

//go:embed schemas/contract.schema.json
var contractSchemaJSON []byte

const specVersion = "0.1"

// runSpec handles the `tass spec` command.
func runSpec(args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: tass spec --version\n")
		return fmt.Errorf("no subcommand given")
	}
	switch args[0] {
	case "--version", "-v", "version":
		fmt.Printf("Capability Manifest Spec v%s\n", specVersion)
		return nil
	default:
		return fmt.Errorf("unknown spec subcommand %q", args[0])
	}
}

// runValidateManifest handles the `tass validate-manifest <path>` command.
// Exits 0 if valid, non-zero with structured errors if not.
func runValidateManifest(args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: tass validate-manifest <path> [--contract]\n")
		return fmt.Errorf("no file path given")
	}

	filePath := args[0]
	useContract := len(args) > 1 && args[1] == "--contract"

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	// Convert YAML → normalized Go value → JSON → re-decoded so the schema
	// validator sees proper JSON types (numbers, strings, booleans, not YAML types).
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}
	raw = normalizeYAML(raw)

	jsonData, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	var jsonVal any
	if err := json.Unmarshal(jsonData, &jsonVal); err != nil {
		return fmt.Errorf("unmarshal JSON: %w", err)
	}

	schemaData := manifestSchemaJSON
	schemaURL := "urn:tass:manifest"
	if useContract {
		schemaData = contractSchemaJSON
		schemaURL = "urn:tass:contract"
	}

	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaURL, bytes.NewReader(schemaData)); err != nil {
		return fmt.Errorf("load schema: %w", err)
	}

	schema, err := c.Compile(schemaURL)
	if err != nil {
		return fmt.Errorf("compile schema: %w", err)
	}

	if err := schema.Validate(jsonVal); err != nil {
		var ve *jsonschema.ValidationError
		if ve, _ = err.(*jsonschema.ValidationError); ve != nil {
			fmt.Fprintf(os.Stderr, "validation failed: %s\n\n", filePath)
			printValidationErrors(ve, 0)
			return fmt.Errorf("invalid")
		}
		return fmt.Errorf("validate: %w", err)
	}

	fmt.Printf("✓ %s is valid\n", filePath)
	return nil
}

func printValidationErrors(ve *jsonschema.ValidationError, depth int) {
	indent := strings.Repeat("  ", depth)
	if ve.Message != "" {
		loc := ve.InstanceLocation
		if loc == "" {
			loc = "(root)"
		}
		fmt.Fprintf(os.Stderr, "%s• %s: %s\n", indent, loc, ve.Message)
	}
	for _, cause := range ve.Causes {
		printValidationErrors(cause, depth+1)
	}
}

// normalizeYAML recursively converts map[interface{}]interface{} (produced by
// gopkg.in/yaml.v3 for untyped YAML maps) to map[string]interface{} so that
// json.Marshal works correctly.
func normalizeYAML(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, vv := range val {
			out[k] = normalizeYAML(vv)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(val))
		for k, vv := range val {
			out[fmt.Sprintf("%v", k)] = normalizeYAML(vv)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, vv := range val {
			out[i] = normalizeYAML(vv)
		}
		return out
	default:
		return v
	}
}
