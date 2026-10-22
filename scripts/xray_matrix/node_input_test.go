package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/nodecheck/report"
	"github.com/xtls/xray-core/infra/conf"
)

const fixtureID = "00000000-0000-4000-8000-000000000001"

func joinedFixture(child string) string {
	return "vless://" + fixtureID + "@127.0.0.1:443?security=tls&type=" +
		url.QueryEscape("tcp#☺️99@synthetic_channel"+child) + "&sni=outer.example.invalid#outer"
}

func TestExpandedInputMatchesUnchangedCoreLoader(t *testing.T) {
	for _, child := range []string{
		"trojan://synthetic@127.0.0.2:443?type=ws&path=%2Fedge#child",
		"vless://" + fixtureID + "@[::1]:8443?type=unknown#unsupported",
		"vless://" + fixtureID + "@127.0.0.2:443?ed=2560&eh=Sec-WebSocket-Protocol",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:synthetic")) + "@127.0.0.2:443#child",
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","add":"127.0.0.2","port":"443","id":"`+fixtureID+`","aid":"0","net":"tcp","type":"none","tls":""}`)),
	} {
		joined := joinedFixture(child)
		entries, err := splitInput(joined)
		if err != nil || len(entries) != 2 || entries[1].URI != child {
			t.Fatal("joined child lost")
		}
		path := filepath.Join(t.TempDir(), "nodes.txt")
		if err := os.WriteFile(path, []byte(joined+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		before, _, err := report.Load(path)
		if err != nil || len(before) != 2 || before[0].Line != 1 || before[1].Line != 1 {
			t.Fatal("fixture does not reproduce old one-record/two-results mismatch")
		}
		var content strings.Builder
		for _, entry := range entries {
			content.WriteString(entry.URI + "\n")
			node, err := conf.DescribeNodeURI(entry.URI)
			if err != nil || entry.Host != node.Address || entry.Port != node.Port {
				t.Fatal("child inherited a different endpoint")
			}
		}
		if err := os.WriteFile(path, []byte(content.String()), 0600); err != nil {
			t.Fatal(err)
		}
		after, _, err := report.Load(path)
		if err != nil || len(after) != len(entries) {
			t.Fatal("prepared input count differs from core loader")
		}
		for i, entry := range entries {
			sum := sha256.Sum256([]byte(entry.URI))
			if after[i].Index != i || after[i].Line != i+1 || after[i].URI != entry.URI ||
				after[i].ID != hex.EncodeToString(sum[:]) || after[i].OriginalURI != "" {
				t.Fatal("prepared count, identity or original bytes differ from core")
			}
		}
	}
}

func TestOrdinaryAndRejectedInputsRemainByteExact(t *testing.T) {
	for _, raw := range []string{
		"trojan://synthetic\x00password@127.0.0.1:443#invalid",
		"vless://" + fixtureID + "@127.0.0.1:443?type=ws&path=/literal-vless://text",
		"vless://" + fixtureID + "@127.0.0.1:443?type=tcp#display-vless://text",
		"trojan://" + url.User("vless://password@literal").String() + "@127.0.0.1:443?type=tcp",
	} {
		entries, err := splitInput(raw)
		if err != nil || !reflect.DeepEqual(entries, []inputEntry{{URI: raw}}) {
			t.Fatal("ordinary/rejected input changed")
		}
	}
	for _, raw := range []string{"", "vless://one\nvless://two", "vless://one\rtwo"} {
		if _, err := splitInput(raw); err == nil {
			t.Fatal("framing error accepted")
		}
	}
}

func TestLiteralJoinedInputAndExpansionBound(t *testing.T) {
	first := "vless://" + fixtureID + "@127.0.0.1:443?type=" + url.QueryEscape("tcp#☺️99@synthetic_channel")
	child := "trojan://synthetic@127.0.0.2:443?type=ws"
	for count := 2; count <= 8; count++ {
		entries, err := splitInput(strings.Repeat(first, count-1) + child)
		if err != nil || len(entries) != count || entries[count-1].URI != child {
			t.Fatal("literal joined entries lost")
		}
		for i := 0; i < count-1; i++ {
			if entries[i].URI != first {
				t.Fatal("literal source bytes changed")
			}
		}
	}
	raw := strings.Repeat(first, 8) + child
	entries, err := splitInput(raw)
	if err != nil || !reflect.DeepEqual(entries, []inputEntry{{URI: raw}}) {
		t.Fatal("core expansion bound bypassed")
	}
}

func TestInputAdapterProvenanceAndFailureCleanup(t *testing.T) {
	dir := t.TempDir()
	source, output := filepath.Join(dir, "source.jsonl"), filepath.Join(dir, "out.jsonl")
	row, err := json.Marshal(map[string]string{"uri": joinedFixture("trojan://synthetic@127.0.0.2:443?type=ws")})
	if err != nil {
		t.Fatal(err)
	}
	data := append(row, '\n')
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepareInput(source, output); err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]string
	lines := strings.Split(strings.TrimSpace(string(result)), "\n")
	sum := sha256.Sum256(data)
	if len(lines) != 2 || json.Unmarshal([]byte(lines[0]), &header) != nil ||
		header["input_sha256"] != hex.EncodeToString(sum[:]) || header["revision"] != coreRevision ||
		header["tool_revision"] != toolRevision || header["schema"] != "vpn-node-input-v1" {
		t.Fatal("input provenance lost")
	}
	if err := prepareInput(source, output); err == nil {
		t.Fatal("existing output overwritten")
	}
	if err := os.WriteFile(source, append(data, []byte("credential-private-invalid-json\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	failed := filepath.Join(dir, "failed.jsonl")
	if err := prepareInput(source, failed); err == nil || strings.Contains(err.Error(), "credential-private") {
		t.Fatal("malformed record accepted or leaked")
	}
	if _, err := os.Stat(failed); !os.IsNotExist(err) {
		t.Fatal("partial preparation left publishable output")
	}
}
