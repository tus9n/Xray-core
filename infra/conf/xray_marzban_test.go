package conf

import (
	"encoding/json"
	"strings"
	"testing"
)

const publicPlainVLESSSettings = `{
	"vnext": [{
		"address": "relay.example.com",
		"port": 10639,
		"users": [{
			"id": "27848739-7e62-4138-9fd3-098a63964b6b",
			"encryption": "none"
		}]
	}]
}`

func buildPublicPlainVLESSOutbound(tag string) error {
	settings := json.RawMessage(publicPlainVLESSSettings)
	_, err := (&OutboundDetourConfig{
		Protocol: "vless",
		Tag:      tag,
		Settings: &settings,
	}).Build()
	return err
}

func TestPublicPlainVLESSStillRejectedForRegularOutbound(t *testing.T) {
	err := buildPublicPlainVLESSOutbound("ordinary-outbound")
	if err == nil || !strings.Contains(err.Error(), "vless without TLS") {
		t.Fatalf("expected public plain VLESS rejection, got %v", err)
	}
}

func TestPublicPlainVLESSAllowedForMarzbanInternalRelay(t *testing.T) {
	if err := buildPublicPlainVLESSOutbound("F_BS1_15"); err != nil {
		t.Fatalf("internal Marzban relay should remain compatible: %v", err)
	}
}
