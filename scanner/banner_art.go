package scanner

import "fmt"

const asciiBanner = `
  ▒█████▒ ▒█████▒ ▒█▒     ▒█▒ ▒█▒ ▒█████▒ ▒██▒  ▒█▒
  ▒█▒     ▒█▒  ▒█▒▒█▒     ▒█▒▒█▒  ▒█▒     ▒█▒█▒ ▒█▒
  ▒████▒  ▒█████▒ ▒█▒     ▒███▒   ▒████▒  ▒█▒ ▒█▒█▒
  ▒█▒     ▒█▒  ▒█▒▒█▒     ▒█▒▒█▒  ▒█▒     ▒█▒  ▒██▒
  ▒█▒     ▒█▒  ▒█▒▒█████▒ ▒█▒ ▒█▒ ▒█████▒ ▒█▒   ▒█▒ v1.0

  Falken // TCP/UDP Reconnaissance Engine
  Author: l4nc3l0t | github.com/J3anP/falken
`

func PrintBanner() {
	fmt.Print(asciiBanner)
}
