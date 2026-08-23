package scanner

import (
	"math"
	"regexp"
	"strings"

	"envguard/backend/parser"
)

// SecretDetection represents a flagged secret with zero raw value exposure
type SecretDetection struct {
	Filename     string `json:"filename"`
	Key          string `json:"key"`
	LineNumber   int    `json:"line_number"`
	SecretType   string `json:"secret_type"`
	Severity     string `json:"severity"` // CRITICAL, HIGH, MEDIUM
	MaskedValue  string `json:"masked_value"`
	EntropyScore float64`json:"entropy_score"`
}

// Known pattern definitions
var (
	awsAccessKeyRegex = regexp.MustCompile(`^(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}$`)
	awsSecretKeyRegex = regexp.MustCompile(`^[A-Za-z0-9/+=]{40}$`)
	stripeKeyRegex    = regexp.MustCompile(`^sk_(live|test)_[0-9a-zA-Z]{24,}$`)
	openAIKeyRegex    = regexp.MustCompile(`^sk-[a-zA-Z0-9]{32,}$`)
	githubTokenRegex  = regexp.MustCompile(`^(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}$`)
	jwtRegex          = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	rsaPrivateRegex   = regexp.MustCompile(`-----BEGIN (RSA )?PRIVATE KEY-----`)
)

// Known secret key name hints
var secretKeyNameHints = []string{
	"SECRET", "PASSWORD", "PASS", "TOKEN", "API_KEY", "APIKEY",
	"PRIVATE_KEY", "DB_PASS", "DATABASE_URL", "AWS_SECRET",
	"STRIPE_KEY", "AUTH_KEY", "CREDS", "CREDENTIAL",
}

// CalculateShannonEntropy calculates string randomness score (0.0 to 8.0)
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return math.Round(entropy*100) / 100
}

// MaskSecret returns a safe masked representation (e.g., AKIA****************)
func MaskSecret(val string) string {
	if len(val) <= 4 {
		return "****"
	}
	prefixLen := 4
	if len(val) < 8 {
		prefixLen = 2
	}
	return val[:prefixLen] + strings.Repeat("*", len(val)-prefixLen)
}

// ScanFileForSecrets scans a parsed .env file using multi-factor evaluation (Regex + Context + Entropy)
func ScanFileForSecrets(parsed parser.ParsedEnv) []SecretDetection {
	detections := make([]SecretDetection, 0)

	for _, entry := range parsed.Entries {
		if entry.IsComment || entry.Value == "" {
			continue
		}

		val := entry.Value
		keyUpper := strings.ToUpper(entry.Key)
		entropy := CalculateShannonEntropy(val)

		// 1. RSA Private Key Detection
		if rsaPrivateRegex.MatchString(val) {
			detections = append(detections, SecretDetection{
				Filename:     parsed.Filename,
				Key:          entry.Key,
				LineNumber:   entry.LineNumber,
				SecretType:   "RSA Private Key",
				Severity:     "CRITICAL",
				MaskedValue:  "-----BEGIN PRIVATE KEY-----*****",
				EntropyScore: entropy,
			})
			continue
		}

		// 2. AWS Access Key ID
		if awsAccessKeyRegex.MatchString(val) {
			detections = append(detections, SecretDetection{
				Filename:     parsed.Filename,
				Key:          entry.Key,
				LineNumber:   entry.LineNumber,
				SecretType:   "AWS Access Key ID",
				Severity:     "CRITICAL",
				MaskedValue:  MaskSecret(val),
				EntropyScore: entropy,
			})
			continue
		}

		// 3. Stripe Secret Key
		if stripeKeyRegex.MatchString(val) {
			detections = append(detections, SecretDetection{
				Filename:     parsed.Filename,
				Key:          entry.Key,
				LineNumber:   entry.LineNumber,
				SecretType:   "Stripe Secret Key",
				Severity:     "CRITICAL",
				MaskedValue:  MaskSecret(val),
				EntropyScore: entropy,
			})
			continue
		}

		// 4. OpenAI Secret Key
		if openAIKeyRegex.MatchString(val) {
			detections = append(detections, SecretDetection{
				Filename:     parsed.Filename,
				Key:          entry.Key,
				LineNumber:   entry.LineNumber,
				SecretType:   "OpenAI API Key",
				Severity:     "CRITICAL",
				MaskedValue:  MaskSecret(val),
				EntropyScore: entropy,
			})
			continue
		}

		// 5. GitHub Personal Token
		if githubTokenRegex.MatchString(val) {
			detections = append(detections, SecretDetection{
				Filename:     parsed.Filename,
				Key:          entry.Key,
				LineNumber:   entry.LineNumber,
				SecretType:   "GitHub Token",
				Severity:     "CRITICAL",
				MaskedValue:  MaskSecret(val),
				EntropyScore: entropy,
			})
			continue
		}

		// 6. JWT Token
		if jwtRegex.MatchString(val) {
			detections = append(detections, SecretDetection{
				Filename:     parsed.Filename,
				Key:          entry.Key,
				LineNumber:   entry.LineNumber,
				SecretType:   "JSON Web Token (JWT)",
				Severity:     "HIGH",
				MaskedValue:  MaskSecret(val),
				EntropyScore: entropy,
			})
			continue
		}

		// 7. Multi-factor Name Context + High Entropy
		hasKeyNameHint := false
		for _, hint := range secretKeyNameHints {
			if strings.Contains(keyUpper, hint) {
				hasKeyNameHint = true
				break
			}
		}

		// Combined check: If key name strongly suggests secret AND value has length > 10 AND entropy > 3.8
		if hasKeyNameHint && len(val) >= 8 && entropy >= 3.8 {
			severity := "HIGH"
			if entropy >= 4.5 {
				severity = "CRITICAL"
			}
			detections = append(detections, SecretDetection{
				Filename:     parsed.Filename,
				Key:          entry.Key,
				LineNumber:   entry.LineNumber,
				SecretType:   "Sensitive Credential",
				Severity:     severity,
				MaskedValue:  MaskSecret(val),
				EntropyScore: entropy,
			})
			continue
		}

		// 8. AWS Secret Key Pattern with Key Context
		if strings.Contains(keyUpper, "AWS") && awsSecretKeyRegex.MatchString(val) {
			detections = append(detections, SecretDetection{
				Filename:     parsed.Filename,
				Key:          entry.Key,
				LineNumber:   entry.LineNumber,
				SecretType:   "AWS Secret Access Key",
				Severity:     "CRITICAL",
				MaskedValue:  MaskSecret(val),
				EntropyScore: entropy,
			})
			continue
		}
	}

	return detections
}

// GenerateSanitizedExample generates clean .env.example content in-memory replacing secrets with placeholders
func GenerateSanitizedExample(parsed parser.ParsedEnv) string {
	var builder strings.Builder

	for _, entry := range parsed.Entries {
		if entry.IsComment {
			builder.WriteString(entry.RawLine)
			builder.WriteString("\n")
			continue
		}

		placeholder := "YOUR_" + strings.ToUpper(entry.Key) + "_HERE"
		builder.WriteString(entry.Key)
		builder.WriteString("=")
		builder.WriteString(placeholder)
		builder.WriteString("\n")
	}

	return builder.String()
}
