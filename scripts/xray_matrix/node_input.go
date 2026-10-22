// VPN-Nodes adapter: build this file against the pinned, unchanged core module.
// Reuse its list reader semantics instead of copying URI interpretation to Python.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xtls/xray-core/infra/conf"
)

var coreRevision = "unknown"
var toolRevision = "unknown"

type inputEntry struct {
	URI      string `json:"uri"`
	Protocol string `json:"protocol,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     uint16 `json:"port,omitempty"`
}

func splitInput(raw string) ([]inputEntry, error) {
	if raw == "" || strings.ContainsAny(raw, "\r\n") {
		return nil, errors.New("invalid input framing")
	}
	parts := conf.SplitNodeURIListLine(raw)
	if len(parts) == 1 && parts[0].URI == raw {
		// Invalid/unsupported ordinary nodes still reach nodecheck for rejection.
		return []inputEntry{{URI: raw}}, nil
	}
	entries := make([]inputEntry, 0, len(parts))
	for _, part := range parts {
		node, err := conf.DescribeNodeURI(part.URI)
		if err != nil || strings.ContainsAny(part.URI, "\r\n") {
			return nil, errors.New("invalid expanded input")
		}
		stable := conf.SplitNodeURIListLine(part.URI)
		if len(stable) != 1 || stable[0].URI != part.URI {
			return nil, errors.New("expanded input is not a single node")
		}
		protocol := node.Protocol
		if protocol == "ss" {
			protocol = "shadowsocks"
		}
		entries = append(entries, inputEntry{URI: part.URI, Protocol: protocol, Host: node.Address, Port: node.Port})
	}
	return entries, nil
}

func prepareInput(input, output string) error {
	f, err := os.Open(input)
	if err != nil {
		return errors.New("cannot open input")
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return errors.New("cannot hash input")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return errors.New("cannot rewind input")
	}
	out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("output must be new")
	}
	complete := false
	defer func() {
		out.Close()
		if !complete {
			os.Remove(output)
		}
	}()
	w := bufio.NewWriter(out)
	encoder := json.NewEncoder(w)
	header := map[string]string{"schema": "vpn-node-input-v1", "revision": coreRevision,
		"tool_revision": toolRevision, "input_sha256": hex.EncodeToString(h.Sum(nil))}
	if err = encoder.Encode(header); err != nil {
		return errors.New("cannot write input header")
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 65536), 2<<20)
	index := 0
	for scanner.Scan() {
		var row struct {
			URI string `json:"uri"`
		}
		if json.Unmarshal(scanner.Bytes(), &row) != nil {
			return errors.New("invalid input record")
		}
		entries, err := splitInput(row.URI)
		if err != nil {
			return err
		}
		if err = encoder.Encode(struct {
			Index   int          `json:"index"`
			Entries []inputEntry `json:"entries"`
		}{index, entries}); err != nil {
			return errors.New("cannot write input record")
		}
		index++
	}
	if scanner.Err() != nil {
		return errors.New("cannot read input records")
	}
	if err = w.Flush(); err != nil {
		return errors.New("cannot flush input records")
	}
	if err = out.Close(); err != nil {
		return errors.New("cannot close input records")
	}
	complete = true
	return nil
}

func main() {
	input := flag.String("input", "", "Private source URI JSONL")
	output := flag.String("output", "", "New private expansion JSONL")
	flag.Parse()
	if flag.NArg() != 0 || *input == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "input and output are required")
		os.Exit(1)
	}
	if err := prepareInput(*input, *output); err != nil {
		// Errors deliberately exclude input bytes, credentials and parser messages.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
