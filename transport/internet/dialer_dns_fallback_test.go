package internet_test

import (
	"context"
	gonet "net"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	. "github.com/xtls/xray-core/transport/internet"
)

type failingDNSClient struct{}

func (*failingDNSClient) Start() error      { return nil }
func (*failingDNSClient) Close() error      { return nil }
func (*failingDNSClient) Type() interface{} { return dns.ClientType() }
func (*failingDNSClient) LookupIP(string, dns.IPOption) ([]xnet.IP, uint32, error) {
	return nil, 0, dns.RCodeError(3)
}

type recordingSystemDialer struct {
	called      bool
	destination xnet.Destination
	peer        gonet.Conn
}

func (d *recordingSystemDialer) Dial(_ context.Context, _ xnet.Address, destination xnet.Destination, _ *SocketConfig) (xnet.Conn, error) {
	d.called = true
	d.destination = destination
	conn, peer := gonet.Pipe()
	d.peer = peer
	return conn, nil
}

func (*recordingSystemDialer) DestIpAddress() xnet.IP { return nil }

type logRecorder struct {
	messages []*log.GeneralMessage
}

func (r *logRecorder) Handle(message log.Message) {
	if general, ok := message.(*log.GeneralMessage); ok {
		r.messages = append(r.messages, general)
	}
}

func (r *logRecorder) has(severity log.Severity, text string) bool {
	for _, message := range r.messages {
		if message.Severity == severity && strings.Contains(message.String(), text) {
			return true
		}
	}
	return false
}

func TestDNSFallbackLogSeverity(t *testing.T) {
	recorder := &logRecorder{}
	log.RegisterHandler(recorder)
	InitSystemDialer(&failingDNSClient{}, nil)
	defer InitSystemDialer(nil, nil)
	defer UseAlternativeSystemDialer(nil)

	destination := xnet.TCPDestination(xnet.DomainAddress("missing.example"), 443)
	dialer := &recordingSystemDialer{}
	UseAlternativeSystemDialer(dialer)
	conn, err := DialSystem(context.Background(), destination, &SocketConfig{DomainStrategy: DomainStrategy_USE_IP4})
	if err != nil {
		t.Fatalf("non-force DNS fallback failed: %v", err)
	}
	conn.Close()
	dialer.peer.Close()
	if !dialer.called || dialer.destination.Address.Domain() != "missing.example" {
		t.Fatalf("system dialer did not receive the original domain: %+v", dialer.destination)
	}
	if !recorder.has(log.Severity_Info, "failed to resolve ip, falling back to system DNS") {
		t.Fatal("non-force DNS failure was not logged at Info level")
	}
	if recorder.has(log.Severity_Error, "failed to resolve ip") {
		t.Fatal("non-force DNS failure was logged at Error level")
	}

	recorder.messages = nil
	dialer = &recordingSystemDialer{}
	UseAlternativeSystemDialer(dialer)
	_, err = DialSystem(context.Background(), destination, &SocketConfig{DomainStrategy: DomainStrategy_FORCE_IP4})
	if err == nil {
		t.Fatal("force-IP DNS failure unexpectedly succeeded")
	}
	if dialer.called {
		t.Fatal("force-IP DNS failure unexpectedly reached the system dialer")
	}
	if !recorder.has(log.Severity_Error, "failed to resolve ip") {
		t.Fatal("force-IP DNS failure was not logged at Error level")
	}
}
