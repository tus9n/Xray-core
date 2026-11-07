package reality

// [MARZBAN] JA4-отпечаток ClientHello (спецификация FoxIO, https://github.com/FoxIO-LLC/ja4).
// Нужен панели, чтобы точно видеть, каким uTLS-отпечатком (qq/ios/chrome/firefox…)
// подключается пользователь: сервер VLESS отпечаток не получает, а в REALITY разобранный
// ClientHello на руках. Порядок шифров/расширений сортируется — отпечаток устойчив к
// перемешиванию расширений (chrome, randomized).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func ja4Hash(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func ja4Join(vals []uint16) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, fmt.Sprintf("%04x", v))
	}
	return strings.Join(parts, ",")
}

func ja4AlpnChars(alpn string) string {
	if alpn == "" {
		return "00"
	}
	first, last := alpn[0], alpn[len(alpn)-1]
	isAlnum := func(c byte) bool {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	if !isAlnum(first) || !isAlnum(last) {
		h := hex.EncodeToString([]byte(alpn))
		return string(h[0]) + string(h[len(h)-1])
	}
	return string(first) + string(last)
}

// ja4 считает JA4 для разобранного ClientHello (TCP).
func ja4(m *clientHelloMsg) string {
	if m == nil {
		return ""
	}
	ver := m.vers
	for _, v := range m.supportedVersions {
		if !isGREASE(v) && v > ver {
			ver = v
		}
	}
	verStr := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}[ver]
	if verStr == "" {
		verStr = "00"
	}
	sni := "i"
	if m.serverName != "" {
		sni = "d"
	}

	ciphers := make([]uint16, 0, len(m.cipherSuites))
	for _, c := range m.cipherSuites {
		if !isGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}
	exts := make([]uint16, 0, len(m.extensions))
	for _, e := range m.extensions {
		if !isGREASE(e) {
			exts = append(exts, e)
		}
	}
	count := func(n int) string {
		if n > 99 {
			n = 99
		}
		return fmt.Sprintf("%02d", n)
	}
	alpn := ""
	if len(m.alpnProtocols) > 0 {
		alpn = m.alpnProtocols[0]
	}
	a := "t" + verStr + sni + count(len(ciphers)) + count(len(exts)) + ja4AlpnChars(alpn)

	sortedCiphers := append([]uint16(nil), ciphers...)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	b := ja4Hash(ja4Join(sortedCiphers))

	sortedExts := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e != extensionServerName && e != extensionALPN {
			sortedExts = append(sortedExts, e)
		}
	}
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })
	cInput := ja4Join(sortedExts)
	sigs := make([]uint16, 0, len(m.supportedSignatureAlgorithms))
	for _, s := range m.supportedSignatureAlgorithms {
		if !isGREASE(uint16(s)) {
			sigs = append(sigs, uint16(s))
		}
	}
	if len(sigs) > 0 {
		cInput += "_" + ja4Join(sigs)
	}
	c := ja4Hash(cInput)
	if len(sortedExts) == 0 {
		c = "000000000000"
	}
	return a + "_" + b + "_" + c
}
