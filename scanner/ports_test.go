package scanner

import (
	"reflect"
	"sort"
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{"puerto único", "80", []int{80}, false},
		{"lista simple", "80,443,22", []int{80, 443, 22}, false},
		{"rango simple", "1-5", []int{1, 2, 3, 4, 5}, false},
		{"mixto lista+rango", "80,1-3,443", []int{80, 1, 2, 3, 443}, false},
		{"duplicados se eliminan", "80,80,443", []int{80, 443}, false},
		{"rango invertido es error", "100-50", nil, true},
		{"puerto 0 es inválido", "0", nil, true},
		{"puerto 65536 es inválido", "65536", nil, true},
		{"puerto 65535 es válido (límite superior)", "65535", []int{65535}, false},
		{"puerto 1 es válido (límite inferior)", "1", []int{1}, false},
		{"texto no numérico es error", "abc", nil, true},
		{"rango con texto es error", "abc-100", nil, true},
		{"top-100 retorna la lista predefinida", "top-100", Top100Ports, false},
		{"string vacío entre comas es error", "80,,443", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("esperaba error, no hubo ninguno")
				}
				return
			}
			if err != nil {
				t.Fatalf("no esperaba error, obtuvo: %v", err)
			}

			if tt.name != "top-100 retorna la lista predefinida" {
				sort.Ints(got)
				sort.Ints(tt.want)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkParsePortsLargeRange(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ParsePorts("1-65535")
	}
}
