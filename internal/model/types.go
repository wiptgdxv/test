package model

// ScanInput is one raw network scan record accepted by the API and client.
type ScanInput struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Fingerprint is the normalized identification result for a scan record.
type Fingerprint struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// UnknownFingerprint returns the required safe fallback result.
func UnknownFingerprint(input ScanInput) Fingerprint {
	return Fingerprint{
		IP:       input.IP,
		Port:     input.Port,
		Protocol: "unknown",
	}
}
