package reporting

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/capsaicin/scanner/internal/scanner"
)

type ScanReport struct {
	SchemaVersion string           `json:"schema_version"`
	RunID         string           `json:"run_id"`
	Metadata      ScanMetadata     `json:"metadata"`
	Results       []scanner.Result `json:"results"`
}

type ScanMetadata struct {
	StartTime    string `json:"start_time"`
	EndTime      string `json:"end_time"`
	TargetCount  int    `json:"target_count"`
	TargetsHash  string `json:"targets_hash"`
	TotalResults int    `json:"total_results"`
	Version      string `json:"version"`
}

func SaveJSON(results []scanner.Result, filename string) error {
	sorted := make([]scanner.Result, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].URL != sorted[j].URL {
			return sorted[i].URL < sorted[j].URL
		}
		return sorted[i].StatusCode < sorted[j].StatusCode
	})

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sorted)
}

func SaveJSONReport(results []scanner.Result, filename string, targets []string, runID string) error {
	sorted := make([]scanner.Result, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].URL != sorted[j].URL {
			return sorted[i].URL < sorted[j].URL
		}
		return sorted[i].StatusCode < sorted[j].StatusCode
	})

	targetsHash := hashStrings(targets)

	report := ScanReport{
		SchemaVersion: "3.0",
		RunID:         runID,
		Metadata: ScanMetadata{
			StartTime:    time.Now().Format(time.RFC3339),
			EndTime:      time.Now().Format(time.RFC3339),
			TargetCount:  len(targets),
			TargetsHash:  targetsHash,
			TotalResults: len(sorted),
			Version:      "3.0.0",
		},
		Results: sorted,
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func hashStrings(ss []string) string {
	h := sha256.New()
	for _, s := range ss {
		h.Write([]byte(s))
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

func GenerateRunID() string {
	h := sha256.New()
	h.Write([]byte(time.Now().Format(time.RFC3339Nano)))
	h.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
}

func SortResults(results []scanner.Result) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].URL != results[j].URL {
			return results[i].URL < results[j].URL
		}
		return results[i].StatusCode < results[j].StatusCode
	})
}

func FormatResultsJSON(results []scanner.Result) (string, error) {
	sorted := make([]scanner.Result, len(results))
	copy(sorted, results)
	SortResults(sorted)

	data, err := json.MarshalIndent(sorted, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func CountByStatus(results []scanner.Result) map[string]int {
	counts := map[string]int{
		"2xx":      0,
		"3xx":      0,
		"4xx":      0,
		"5xx":      0,
		"critical": 0,
		"secrets":  0,
		"waf":      0,
	}

	for _, r := range results {
		switch {
		case r.StatusCode >= 200 && r.StatusCode < 300:
			counts["2xx"]++
		case r.StatusCode >= 300 && r.StatusCode < 400:
			counts["3xx"]++
		case r.StatusCode >= 400 && r.StatusCode < 500:
			counts["4xx"]++
		case r.StatusCode >= 500:
			counts["5xx"]++
		}
		if r.Critical {
			counts["critical"]++
		}
		if r.SecretFound {
			counts["secrets"]++
		}
		if r.WAFDetected != "" {
			counts["waf"]++
		}
	}

	_ = strings.TrimSpace

	return counts
}
