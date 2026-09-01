// StoaGraph — one Go module for the whole backend (Planning/26).
//
//   stag/     the GATE: deterministic kernel, MCP gating proxy, control plane. NO model, NO keys.
//   harness/  the ORCHESTRATOR: dispatcher, agent loop, models. Holds the keys.
//   cmd/      the binaries — each ships as its own container, so the topology is demonstrated,
//             not hidden. The dependency runs ONE WAY only: harness -> stag, never the reverse.
module github.com/curtisslone/stoagraph/stoa-kernel

go 1.25.0

require (
	github.com/anthropics/anthropic-sdk-go v1.57.0
	github.com/modelcontextprotocol/go-sdk v1.6.1
	go.yaml.in/yaml/v3 v3.0.4
	modernc.org/sqlite v1.53.0
)

require (
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/invopop/jsonschema v0.14.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/standard-webhooks/standard-webhooks/libraries v0.0.1 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.2 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	modernc.org/libc v1.73.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
