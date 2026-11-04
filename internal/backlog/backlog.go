// Package backlog loads the linux_vulnerability_evidence_matrix.csv task
// matrix and converts it into a validated, machine-readable implementation
// backlog. The CSV is the authoritative planning artifact for the resolver.
package backlog

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ResolverBacklogItem is the internal task model for one CSV row.
type ResolverBacklogItem struct {
	// TaskID is a stable identifier derived from the row position and the
	// "Collected Information" column (e.g. "T02-binary-package-exact-version").
	TaskID               string   `json:"task_id"`
	RowNumber            int      `json:"row_number"` // 1-based CSV data row (header excluded)
	CollectedInformation string   `json:"collected_information"`
	VulnerabilityType    string   `json:"vulnerability_type"`
	DecisionRule         string   `json:"decision_rule"`
	Implementation       string   `json:"implementation_approach"`
	Difficulty           int      `json:"difficulty"`
	DifficultyRaw        string   `json:"difficulty_raw"`
	EdgeCases            []string `json:"edge_cases"`
	PrimaryDataSources   []string `json:"primary_data_sources"`
}

// ValidationIssue is a single problem detected while validating the CSV.
type ValidationIssue struct {
	RowNumber int    `json:"row_number"`
	TaskID    string `json:"task_id,omitempty"`
	Severity  string `json:"severity"` // "error" | "warning"
	Message   string `json:"message"`
}

// Backlog is the parsed and validated task matrix.
type Backlog struct {
	SourceFile    string                `json:"source_file"`
	Items         []ResolverBacklogItem `json:"items"`
	Issues        []ValidationIssue     `json:"issues"`
	UnknownColumn []string              `json:"unknown_columns,omitempty"`
}

var requiredColumns = []string{
	"Collected Information",
	"Vulnerability Type",
	"Vulnerable Decision Rule",
	"Implementation Approach",
	"Difficulty",
	"Critical Edge Cases",
	"Primary Data Sources",
}

var difficultyRe = regexp.MustCompile(`^\s*([1-5])\s*/\s*5\s*$`)

// ParseDifficulty converts values such as "3/5" into 3.
func ParseDifficulty(raw string) (int, error) {
	m := difficultyRe.FindStringSubmatch(raw)
	if m == nil {
		return 0, fmt.Errorf("invalid difficulty value %q (expected N/5 with N in 1..5)", raw)
	}
	return int(m[1][0] - '0'), nil
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = strings.ToLower(s)
	s = slugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 48 {
		s = s[:48]
		s = strings.Trim(s, "-")
	}
	return s
}

// splitList breaks a free-text cell into structured entries. The CSV uses ";"
// as the strong separator; we keep comma-separated fragments together unless
// no semicolon exists at all.
func splitList(cell string) []string {
	cell = strings.TrimSpace(cell)
	if cell == "" {
		return nil
	}
	sep := ";"
	if !strings.Contains(cell, ";") {
		sep = ","
	}
	parts := strings.Split(cell, sep)
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Load reads and validates the CSV backlog file.
// Unknown columns are reported but never break parsing.
func Load(path string) (*Backlog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open backlog csv: %w", err)
	}
	defer f.Close()
	b, err := Parse(f)
	if err != nil {
		return nil, err
	}
	b.SourceFile = filepath.Base(path)
	return b, nil
}

// Parse reads and validates CSV content from a reader.
func Parse(r io.Reader) (*Backlog, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read csv: %w", err)
	}
	// Strip a UTF-8 BOM if present (spreadsheet exports commonly add one).
	raw = []byte(strings.TrimPrefix(string(raw), "\ufeff"))
	cr := csv.NewReader(strings.NewReader(string(raw)))
	cr.FieldsPerRecord = -1 // tolerate ragged rows; validated per-row below
	records, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse csv: %w", err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("csv is empty")
	}

	header := records[0]
	colIdx := map[string]int{}
	for i, h := range header {
		colIdx[strings.TrimSpace(h)] = i
	}
	b := &Backlog{}
	for _, h := range header {
		known := false
		for _, req := range requiredColumns {
			if strings.TrimSpace(h) == req {
				known = true
				break
			}
		}
		if !known && strings.TrimSpace(h) != "" {
			b.UnknownColumn = append(b.UnknownColumn, strings.TrimSpace(h))
		}
	}
	var missing []string
	for _, req := range requiredColumns {
		if _, ok := colIdx[req]; !ok {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("required columns missing from csv header: %s", strings.Join(missing, ", "))
	}

	get := func(row []string, col string) string {
		i := colIdx[col]
		if i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}

	seen := map[string]int{} // duplicate detection key -> first row number
	for n, row := range records[1:] {
		rowNum := n + 1
		// Skip fully empty trailing rows.
		empty := true
		for _, c := range row {
			if strings.TrimSpace(c) != "" {
				empty = false
				break
			}
		}
		if empty {
			continue
		}

		item := ResolverBacklogItem{
			RowNumber:            rowNum,
			CollectedInformation: get(row, "Collected Information"),
			VulnerabilityType:    get(row, "Vulnerability Type"),
			DecisionRule:         get(row, "Vulnerable Decision Rule"),
			Implementation:       get(row, "Implementation Approach"),
			DifficultyRaw:        get(row, "Difficulty"),
			EdgeCases:            splitList(get(row, "Critical Edge Cases")),
			PrimaryDataSources:   splitList(get(row, "Primary Data Sources")),
		}
		item.TaskID = fmt.Sprintf("T%02d-%s", rowNum, slugify(item.CollectedInformation))

		issue := func(sev, msg string) {
			b.Issues = append(b.Issues, ValidationIssue{RowNumber: rowNum, TaskID: item.TaskID, Severity: sev, Message: msg})
		}

		if item.CollectedInformation == "" {
			issue("error", "Collected Information is empty")
		}
		if item.DecisionRule == "" {
			issue("error", "Vulnerable Decision Rule is empty")
		}
		if item.Implementation == "" {
			issue("error", "Implementation Approach is empty")
		}
		if len(item.PrimaryDataSources) == 0 {
			issue("error", "at least one Primary Data Source is required")
		}
		d, derr := ParseDifficulty(item.DifficultyRaw)
		if derr != nil {
			issue("error", derr.Error())
		} else {
			item.Difficulty = d
		}

		dupKey := strings.ToLower(item.CollectedInformation) + "|" + strings.ToLower(item.VulnerabilityType)
		if first, dup := seen[dupKey]; dup {
			issue("warning", fmt.Sprintf("duplicate task: same Collected Information + Vulnerability Type as row %d", first))
		} else {
			seen[dupKey] = rowNum
		}

		b.Items = append(b.Items, item)
	}
	if len(b.Items) == 0 {
		return nil, fmt.Errorf("csv contains a header but no task rows")
	}
	return b, nil
}

// Errors returns only error-severity issues.
func (b *Backlog) Errors() []ValidationIssue {
	var out []ValidationIssue
	for _, i := range b.Issues {
		if i.Severity == "error" {
			out = append(out, i)
		}
	}
	return out
}

// WriteJSON writes the machine-readable backlog (build/backlog.json).
func (b *Backlog) WriteJSON(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// WritePlan writes a human-readable implementation plan, ordered by difficulty then row.
func (b *Backlog) WritePlan(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	items := make([]ResolverBacklogItem, len(b.Items))
	copy(items, b.Items)
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Difficulty != items[j].Difficulty {
			return items[i].Difficulty < items[j].Difficulty
		}
		return items[i].RowNumber < items[j].RowNumber
	})

	var sb strings.Builder
	sb.WriteString("# Generated Linux Resolver Implementation Plan\n\n")
	sb.WriteString("Generated from `" + b.SourceFile + "`. Do not edit by hand.\n\n")
	sb.WriteString(fmt.Sprintf("Total tasks: %d. Ordered by difficulty ascending, then CSV row order.\n\n", len(items)))
	if len(b.Issues) > 0 {
		sb.WriteString("## Validation issues\n\n")
		for _, is := range b.Issues {
			sb.WriteString(fmt.Sprintf("- row %d (%s) [%s]: %s\n", is.RowNumber, is.TaskID, is.Severity, is.Message))
		}
		sb.WriteString("\n")
	}
	for _, it := range items {
		sb.WriteString(fmt.Sprintf("## %s (difficulty %d/5)\n\n", it.TaskID, it.Difficulty))
		sb.WriteString(fmt.Sprintf("- **Collected information:** %s\n", it.CollectedInformation))
		sb.WriteString(fmt.Sprintf("- **Vulnerability type:** %s\n", it.VulnerabilityType))
		sb.WriteString(fmt.Sprintf("- **Decision rule:** %s\n", it.DecisionRule))
		sb.WriteString(fmt.Sprintf("- **Implementation approach:** %s\n", it.Implementation))
		if len(it.EdgeCases) > 0 {
			sb.WriteString("- **Critical edge cases:**\n")
			for _, e := range it.EdgeCases {
				sb.WriteString("  - " + e + "\n")
			}
		}
		if len(it.PrimaryDataSources) > 0 {
			sb.WriteString("- **Primary data sources:**\n")
			for _, s := range it.PrimaryDataSources {
				sb.WriteString("  - " + s + "\n")
			}
		}
		sb.WriteString("\n")
	}
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}
