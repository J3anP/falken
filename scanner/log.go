package scanner

import "fmt"

const (
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
)

func LogInfo(format string, a ...interface{}) {
	fmt.Printf(colorYellow+"[*] "+colorReset+format+"\n", a...)
}

func LogSuccess(format string, a ...interface{}) {
	fmt.Printf(colorGreen+"[+] "+colorReset+format+"\n", a...)
}

func LogError(format string, a ...interface{}) {
	fmt.Printf(colorRed+"[-] "+colorReset+format+"\n", a...)
}
