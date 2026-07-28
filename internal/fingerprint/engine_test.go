package fingerprint

import (
	"path/filepath"
	"testing"

	"banner-fingerprint/internal/model"
	"banner-fingerprint/internal/rules"
)

func TestIdentifyRequiredFingerprints(t *testing.T) {
	engine := testEngine(t)
	tests := []struct {
		name       string
		input      model.ScanInput
		protocol   string
		product    string
		version    string
		osHint     string
		confidence float64
	}{
		{
			name: "OpenSSH on Ubuntu", input: model.ScanInput{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"},
			protocol: "SSH", product: "OpenSSH", version: "8.9p1", osHint: "Ubuntu", confidence: 0.95,
		},
		{
			name: "nginx", input: model.ScanInput{IP: "1.2.3.5", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"},
			protocol: "HTTP", product: "nginx", version: "1.24.0", confidence: 0.9,
		},
		{
			name: "Apache", input: model.ScanInput{IP: "1.2.3.6", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Unix)\r\n\r\n"},
			protocol: "HTTP", product: "Apache", version: "2.4.57", confidence: 0.9,
		},
		{
			name: "Jetty", input: model.ScanInput{IP: "1.2.3.10", Port: 8080, Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty(9.4.51.v20230217)\r\n\r\n"},
			protocol: "HTTP", product: "Jetty", version: "9.4.51", confidence: 0.85,
		},
		{
			name: "MySQL packet-framed handshake", input: model.ScanInput{IP: "1.2.3.7", Port: 3306, Banner: "J\x00\x00\x00\x0a8.0.32\x00"},
			protocol: "MySQL", product: "MySQL", version: "8.0.32", confidence: 0.9,
		},
		{
			name: "Redis error", input: model.ScanInput{IP: "1.2.3.8", Port: 6379, Banner: "-ERR wrong number of arguments for 'get' command"},
			protocol: "Redis", product: "Redis", confidence: 0.7,
		},
		{
			name: "ProFTPD repeated product", input: model.ScanInput{IP: "1.2.3.9", Port: 21, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"},
			protocol: "FTP", product: "ProFTPD", version: "1.3.7", confidence: 0.9,
		},
		{
			name: "Microsoft IIS", input: model.ScanInput{IP: "1.2.3.20", Port: 8888, Banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"},
			protocol: "HTTP", product: "Microsoft-IIS", version: "10.0", osHint: "Windows", confidence: 0.88,
		},
		{
			name: "Pure FTPd", input: model.ScanInput{IP: "1.2.3.22", Port: 21, Banner: "220 Welcome to Pure-FTPd"},
			protocol: "FTP", product: "Pure-FTPd", confidence: 0.88,
		},
		{
			name: "unknown", input: model.ScanInput{IP: "1.2.3.11", Port: 12345, Banner: "unrecognized service"},
			protocol: "unknown", confidence: 0,
		},
		{
			name: "empty banner", input: model.ScanInput{IP: "1.2.3.12", Port: 0, Banner: ""},
			protocol: "unknown", confidence: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.Identify(tt.input)
			if got.IP != tt.input.IP || got.Port != tt.input.Port {
				t.Fatalf("identity fields changed: %#v", got)
			}
			if got.Protocol != tt.protocol || got.Product != tt.product || got.Version != tt.version || got.OSHint != tt.osHint || got.Confidence != tt.confidence {
				t.Fatalf("unexpected fingerprint:\n got  %#v\n want protocol=%q product=%q version=%q os=%q confidence=%v", got, tt.protocol, tt.product, tt.version, tt.osHint, tt.confidence)
			}
		})
	}
}

func TestIdentifyUsesPortOnlyAsHint(t *testing.T) {
	got := testEngine(t).Identify(model.ScanInput{Port: 12345, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.25.4\r\n\r\n"})
	if got.Product != "nginx" || got.Protocol != "HTTP" {
		t.Fatalf("strong banner was not recognized on an unusual port: %#v", got)
	}
	if got.Confidence != 0.85 {
		t.Fatalf("expected port penalty, got confidence %v", got.Confidence)
	}
}

func TestIdentifyBatchPreservesLengthAndOrder(t *testing.T) {
	inputs := []model.ScanInput{
		{IP: "first", Port: 22, Banner: "SSH-2.0-OpenSSH_9.8p1"},
		{IP: "second", Port: 9, Banner: "garbage"},
	}
	got := testEngine(t).IdentifyBatch(inputs)
	if len(got) != len(inputs) || got[0].IP != "first" || got[1].IP != "second" || got[1].Protocol != "unknown" {
		t.Fatalf("unexpected batch: %#v", got)
	}
}

func testEngine(t *testing.T) *Engine {
	t.Helper()
	set, err := rules.LoadFile(filepath.Join("..", "..", "configs", "fingerprints.json"))
	if err != nil {
		t.Fatalf("load test rules: %v", err)
	}
	return NewEngine(set)
}
