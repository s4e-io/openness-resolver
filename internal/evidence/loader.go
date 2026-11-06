package evidence

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// SupportedSchemaMajor is the collector evidence schema major this resolver
// understands. A different major may change field meaning, so it is refused
// instead of being resolved into a misleading result.
const SupportedSchemaMajor = "1"

// MaxEvidenceBytes matches the desktop's limit on evidence fetched from a host.
const MaxEvidenceBytes = 64 << 20

// RecordError describes a single record that failed to decode. Record errors
// never abort document loading; the resolver reports them and continues.
type RecordError struct {
	Category   string `json:"category"`
	EvidenceID string `json:"evidence_id"`
	Message    string `json:"message"`
}

// LoadResult wraps a parsed document plus per-record decode failures.
type LoadResult struct {
	Doc          *Document
	RecordErrors []RecordError
}

// Load reads and decodes a .openness file.
func Load(path string) (*LoadResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open evidence file: %w", err)
	}
	defer f.Close()
	return Parse(f)
}

// Parse decodes a .openness document from a reader.
func Parse(r io.Reader) (*LoadResult, error) {
	var doc Document
	limited := &io.LimitedReader{R: r, N: MaxEvidenceBytes + 1}
	dec := json.NewDecoder(limited)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode .openness document: %w", err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("invalid .openness document: trailing JSON value")
		}
		return nil, fmt.Errorf("invalid .openness document: trailing data: %w", err)
	}
	if limited.N == 0 {
		return nil, fmt.Errorf(".openness document exceeds %d bytes", MaxEvidenceBytes)
	}
	if doc.SchemaVersion == "" {
		return nil, fmt.Errorf("invalid .openness document: schema_version missing")
	}
	if major, _, _ := strings.Cut(strings.TrimSpace(doc.SchemaVersion), "."); major != SupportedSchemaMajor {
		return nil, fmt.Errorf("unsupported .openness schema_version %q: this resolver reads %s.x", doc.SchemaVersion, SupportedSchemaMajor)
	}
	return &LoadResult{Doc: &doc}, nil
}

// decodeValue decodes a record value into out; on failure it records the
// error in errs and returns false.
func decodeValue(rec Record, category string, out any, errs *[]RecordError) bool {
	if len(rec.Value) == 0 {
		*errs = append(*errs, RecordError{Category: category, EvidenceID: rec.EvidenceID, Message: "record has no value payload"})
		return false
	}
	if err := json.Unmarshal(rec.Value, out); err != nil {
		*errs = append(*errs, RecordError{Category: category, EvidenceID: rec.EvidenceID, Message: err.Error()})
		return false
	}
	return true
}

// TypedRecord pairs a decoded value with its evidence envelope.
type TypedRecord[T any] struct {
	EvidenceID       string
	ObservedAt       string
	CollectionStatus string
	Value            T
}

func decodeAll[T any](recs []Record, category string, errs *[]RecordError) []TypedRecord[T] {
	out := make([]TypedRecord[T], 0, len(recs))
	for _, rec := range recs {
		var v T
		if decodeValue(rec, category, &v, errs) {
			out = append(out, TypedRecord[T]{
				EvidenceID:       rec.EvidenceID,
				ObservedAt:       rec.ObservedAt,
				CollectionStatus: rec.CollectionStatus,
				Value:            v,
			})
		}
	}
	return out
}

// Typed accessors. Each returns decoded records and appends decode failures
// to the shared RecordErrors slice.

func (lr *LoadResult) PackageRecords() []TypedRecord[PackageValue] {
	return decodeAll[PackageValue](lr.Doc.Packages, "packages", &lr.RecordErrors)
}

func (lr *LoadResult) ProcessRecords() []TypedRecord[ProcessValue] {
	return decodeAll[ProcessValue](lr.Doc.Processes, "processes", &lr.RecordErrors)
}

func (lr *LoadResult) ServiceRecords() []TypedRecord[ServiceValue] {
	return decodeAll[ServiceValue](lr.Doc.Services, "services", &lr.RecordErrors)
}

func (lr *LoadResult) ListeningPortRecords() []TypedRecord[ListeningPortValue] {
	return decodeAll[ListeningPortValue](lr.Doc.ListeningPorts, "listening_ports", &lr.RecordErrors)
}

func (lr *LoadResult) ContainerRecords() []TypedRecord[ContainerValue] {
	return decodeAll[ContainerValue](lr.Doc.Containers, "containers", &lr.RecordErrors)
}

func (lr *LoadResult) LoadedLibraryRecords() []TypedRecord[LoadedLibrariesValue] {
	return decodeAll[LoadedLibrariesValue](lr.Doc.LoadedLibraries, "loaded_libraries", &lr.RecordErrors)
}

// SoftwareInventoryRecords returns catalog-detected software instances
// (schema 1.5.0+). Summary rows are skipped.
func (lr *LoadResult) SoftwareInventoryRecords() []TypedRecord[SoftwareInstanceValue] {
	all := decodeAll[SoftwareInstanceValue](lr.Doc.SoftwareInventory, "software_inventory", &lr.RecordErrors)
	out := all[:0]
	for _, r := range all {
		if r.Value.EntityType == "software_instance" {
			out = append(out, r)
		}
	}
	return out
}

func (lr *LoadResult) EvidenceChainRecords() []TypedRecord[EvidenceChainValue] {
	return decodeAll[EvidenceChainValue](lr.Doc.EvidenceChains, "evidence_chains", &lr.RecordErrors)
}
