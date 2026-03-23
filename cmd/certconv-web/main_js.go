//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/nickromney/certconv/internal/webapi"
)

func main() {
	js.Global().Set("certconvInvoke", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 1 {
			resp, _ := json.Marshal(webapi.Response{OK: false, Error: "expected a single JSON request argument"})
			return string(resp)
		}

		var req webapi.Request
		if err := json.Unmarshal([]byte(args[0].String()), &req); err != nil {
			resp, _ := json.Marshal(webapi.Response{OK: false, Error: "invalid request JSON: " + err.Error()})
			return string(resp)
		}

		resp, _ := json.Marshal(webapi.Invoke(req))
		return string(resp)
	}))

	js.Global().Set("certconvReady", js.ValueOf(true))
	select {}
}
