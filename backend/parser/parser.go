package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// EnvEntry represents a single key-value entry parsed in memory
type EnvEntry struct {
	Key        string
	Value      string
	LineNumber int
	RawLine    string
	IsComment  bool
	HasSyntax  bool
	SyntaxErr  string
}

// ParsedEnv represents the parsed structure of one .env file
type ParsedEnv struct {
	Filename   string
	Entries    []EnvEntry
	KeyMap     map[string]string
	LineErrors []string
}

// ParseEnvFile parses the raw byte content of a .env file strictly in-memory
func ParseEnvFile(filename string, content []byte) ParsedEnv {
	parsed := ParsedEnv{
		Filename:   filename,
		Entries:    make([]EnvEntry, 0),
		KeyMap:     make(map[string]string),
		LineErrors: make([]string, 0),
	}

	reader := bufio.NewReader(bytes.NewReader(content))
	lineNumber := 0
	var multiLineKey string
	var multiLineVal strings.Builder
	inMultiLine := false

	for {
		lineBytes, isPrefix, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		lineNumber++

		line := string(lineBytes)
		for isPrefix {
			moreBytes, prefix, _ := reader.ReadLine()
			line += string(moreBytes)
			isPrefix = prefix
		}

		trimmed := strings.TrimSpace(line)

		// Handle active multiline double-quoted parsing
		if inMultiLine {
			if strings.HasSuffix(trimmed, "\"") && !strings.HasSuffix(trimmed, "\\\"") {
				multiLineVal.WriteString("\n")
				multiLineVal.WriteString(strings.TrimSuffix(line, "\""))
				finalVal := multiLineVal.String()
				parsed.Entries = append(parsed.Entries, EnvEntry{
					Key:        multiLineKey,
					Value:      finalVal,
					LineNumber: lineNumber,
					RawLine:    multiLineKey + "=\"" + finalVal + "\"",
				})
				parsed.KeyMap[multiLineKey] = finalVal
				inMultiLine = false
				multiLineKey = ""
				multiLineVal.Reset()
			} else {
				multiLineVal.WriteString("\n")
				multiLineVal.WriteString(line)
			}
			continue
		}

		// Comment or empty line
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			parsed.Entries = append(parsed.Entries, EnvEntry{
				LineNumber: lineNumber,
				RawLine:    line,
				IsComment:  true,
			})
			continue
		}

		// Look for key=value separator
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) < 2 {
			parsed.LineErrors = append(parsed.LineErrors, fmt.Sprintf("Line %d: Invalid syntax (missing '=' assignment)", lineNumber))
			parsed.Entries = append(parsed.Entries, EnvEntry{
				LineNumber: lineNumber,
				RawLine:    line,
				HasSyntax:  true,
				SyntaxErr:  "Missing '=' assignment",
			})
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		// Check for key formatting validity (e.g. no spaces inside key name)
		if strings.ContainsAny(key, " \t") {
			parsed.LineErrors = append(parsed.LineErrors, fmt.Sprintf("Line %d: Key '%s' contains invalid whitespace", lineNumber, key))
		}

		// Check for multi-line starting quote
		if strings.HasPrefix(val, "\"") && !strings.HasSuffix(val, "\"") {
			inMultiLine = true
			multiLineKey = key
			multiLineVal.WriteString(strings.TrimPrefix(val, "\""))
			continue
		}

		// Clean quotes for single-line values
		cleanVal := val
		if (strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"")) ||
			(strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")) {
			if len(val) >= 2 {
				cleanVal = val[1 : len(val)-1]
			}
		} else {
			// Strip inline comments if unquoted
			if idx := strings.Index(cleanVal, " #"); idx != -1 {
				cleanVal = strings.TrimSpace(cleanVal[:idx])
			}
		}

		parsed.Entries = append(parsed.Entries, EnvEntry{
			Key:        key,
			Value:      cleanVal,
			LineNumber: lineNumber,
			RawLine:    line,
		})
		parsed.KeyMap[key] = cleanVal
	}

	return parsed
}

// DriftMatrixRow represents key availability across multiple environment files
type DriftMatrixRow struct {
	Key     string            `json:"key"`
	Status  map[string]bool   `json:"status"`  // filename -> exists
	Values  map[string]string `json:"values"`  // filename -> masked/placeholder value info
	Missing []string          `json:"missing"` // list of filenames where key is missing
}

// CalculateDriftMatrix calculates key consistency across multiple parsed .env files
func CalculateDriftMatrix(parsedFiles []ParsedEnv) []DriftMatrixRow {
	allKeysMap := make(map[string]bool)
	for _, file := range parsedFiles {
		for key := range file.KeyMap {
			allKeysMap[key] = true
		}
	}

	rows := make([]DriftMatrixRow, 0, len(allKeysMap))
	for key := range allKeysMap {
		status := make(map[string]bool)
		missing := make([]string, 0)

		for _, file := range parsedFiles {
			_, exists := file.KeyMap[key]
			status[file.Filename] = exists
			if !exists {
				missing = append(missing, file.Filename)
			}
		}

		rows = append(rows, DriftMatrixRow{
			Key:     key,
			Status:  status,
			Missing: missing,
		})
	}

	return rows
}
