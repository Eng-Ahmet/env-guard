package handlers

import (
	"fmt"
	"io"
	"mime/multipart"

	"github.com/gofiber/fiber/v2"

	"envguard/backend/parser"
	"envguard/backend/scanner"
)

// AuditResponse represents the sanitized HTTP response payload
type AuditResponse struct {
	TotalFiles       int                       `json:"total_files"`
	FilesParsed      []string                  `json:"files_parsed"`
	TotalSecrets     int                       `json:"total_secrets"`
	SecretDetections []scanner.SecretDetection `json:"secret_detections"`
	DriftMatrix      []parser.DriftMatrixRow   `json:"drift_matrix"`
	SyntaxErrors     map[string][]string       `json:"syntax_errors"`
}

// SanitizeResponse represents the sanitized .env.example output
type SanitizeResponse struct {
	Filename         string `json:"filename"`
	SanitizedContent string `json:"sanitized_content"`
}

// HandleHealth returns application readiness
func HandleHealth(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "UP",
		"service": "EnvGuard Security Auditor",
		"mode":    "Stateless In-Memory",
	})
}

// HandleAudit processes multi-file multipart/form-data uploads strictly in RAM
func HandleAudit(c *fiber.Ctx) error {
	form, err := c.MultipartForm()
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse multipart/form-data request",
		})
	}

	files := form.File["files"]
	if len(files) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "No files provided in request field 'files'",
		})
	}

	parsedFiles := make([]parser.ParsedEnv, 0, len(files))
	allDetections := make([]scanner.SecretDetection, 0)
	syntaxErrorsMap := make(map[string][]string)
	parsedNames := make([]string, 0, len(files))

	for _, fileHeader := range files {
		// Read content strictly in RAM memory stream
		content, readErr := readMultipartInMemory(fileHeader)
		if readErr != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": fmt.Sprintf("Failed to read file '%s' in memory", fileHeader.Filename),
			})
		}

		// Parse file in memory
		parsed := parser.ParseEnvFile(fileHeader.Filename, content)
		parsedFiles = append(parsedFiles, parsed)
		parsedNames = append(parsedNames, fileHeader.Filename)

		if len(parsed.LineErrors) > 0 {
			syntaxErrorsMap[fileHeader.Filename] = parsed.LineErrors
		}

		// Scan for secrets in memory
		detections := scanner.ScanFileForSecrets(parsed)
		allDetections = append(allDetections, detections...)
	}

	// Calculate drift matrix across uploaded files
	driftMatrix := parser.CalculateDriftMatrix(parsedFiles)

	response := AuditResponse{
		TotalFiles:       len(files),
		FilesParsed:      parsedNames,
		TotalSecrets:     len(allDetections),
		SecretDetections: allDetections,
		DriftMatrix:      driftMatrix,
		SyntaxErrors:     syntaxErrorsMap,
	}

	// Zero log statement of secrets or request body
	return c.Status(fiber.StatusOK).JSON(response)
}

// HandleSanitize processes a single .env file and returns a sanitized .env.example template
func HandleSanitize(c *fiber.Ctx) error {
	form, err := c.MultipartForm()
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse multipart/form-data request",
		})
	}

	files := form.File["files"]
	if len(files) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "No file provided in request field 'files'",
		})
	}

	targetFile := files[0]
	content, readErr := readMultipartInMemory(targetFile)
	if readErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to read uploaded file in memory",
		})
	}

	parsed := parser.ParseEnvFile(targetFile.Filename, content)
	sanitizedText := scanner.GenerateSanitizedExample(parsed)

	return c.Status(fiber.StatusOK).JSON(SanitizeResponse{
		Filename:         targetFile.Filename + ".example",
		SanitizedContent: sanitizedText,
	})
}

// readMultipartInMemory reads multipart FileHeader directly into a RAM byte slice without writing to disk
func readMultipartInMemory(fh *multipart.FileHeader) ([]byte, error) {
	file, err := fh.Open()
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read content directly into memory buffer
	buf := make([]byte, fh.Size)
	_, err = io.ReadFull(file, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}

	return buf, nil
}
