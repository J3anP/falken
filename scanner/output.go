package scanner

import (
	"encoding/json"
	"fmt"
	"os"
)

func ExportJSON(report ScanReport, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("no se pudo crear archivo de salida: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
