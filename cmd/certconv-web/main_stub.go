//go:build !js || !wasm

package main

import "fmt"

func main() {
	fmt.Println("certconv-web is built for GOOS=js GOARCH=wasm and loaded by the web frontend.")
}
