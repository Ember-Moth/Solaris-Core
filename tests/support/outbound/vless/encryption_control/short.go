package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/proxy/vless/encryption"
)

// probeShort preserves the exact caller payload, address, appearance and RTT
// policy. Its first connection is full; subsequent 0-RTT connections reuse the
// same independently implemented client's ticket. It does not implement Vision.
// supported=false distinguishes unsupported/invalid input from network evidence.
func probeShort() (supported bool, result error) {
	if len(os.Args) != 8 {
		return false, fmt.Errorf("probe-short peer encryption ca numeric-target payload rounds")
	}
	parts := strings.Split(os.Args[3], ".")
	if len(parts) < 4 || parts[0] != "mlkem768x25519plus" {
		return false, fmt.Errorf("unsupported encryption family")
	}
	mode := uint32(0)
	switch parts[1] {
	case "native":
	case "xorpub":
		mode = 1
	case "random":
		mode = 2
	default:
		return false, fmt.Errorf("unsupported appearance")
	}
	seconds := uint32(0)
	switch parts[2] {
	case "1rtt":
	case "0rtt":
		seconds = 1
	default:
		return false, fmt.Errorf("unsupported RTT policy")
	}
	var publicKeys [][]byte
	var padding []string
	for _, part := range parts[3:] {
		if len(part) < 20 {
			if len(publicKeys) != 0 {
				return false, fmt.Errorf("padding after a key is unsupported")
			}
			padding = append(padding, part)
		} else {
			key, err := base64.RawURLEncoding.DecodeString(part)
			if err != nil {
				return false, fmt.Errorf("invalid key encoding")
			}
			publicKeys = append(publicKeys, key)
		}
	}
	host, port, err := net.SplitHostPort(os.Args[5])
	if err != nil || net.ParseIP(host) == nil {
		return false, fmt.Errorf("numeric UDP target required")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return false, fmt.Errorf("invalid UDP target port")
	}
	rounds, err := strconv.Atoi(os.Args[7])
	if err != nil || rounds < 1 || rounds > 32 {
		return false, fmt.Errorf("round count outside 1..32")
	}
	payload := []byte(os.Args[6])
	if len(payload) == 0 || len(payload) > 65507 {
		return false, fmt.Errorf("nonempty bounded payload required")
	}
	var roots *x509.CertPool
	if os.Args[4] != "-" {
		pem, err := os.ReadFile(os.Args[4])
		if err != nil {
			return false, fmt.Errorf("trust file could not be read")
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return false, fmt.Errorf("invalid trust bundle")
		}
	}
	clients := [2]*encryption.ClientInstance{}
	for i := range clients {
		clients[i] = &encryption.ClientInstance{}
		if err := clients[i].Init(publicKeys, mode, seconds, strings.Join(padding, ".")); err != nil {
			return false, fmt.Errorf("unsupported encryption parameters: %w", err)
		}
	}
	target := M.ParseSocksaddr(os.Args[5])
	results := make(chan error, len(clients))
	for worker, client := range clients {
		go func(worker int, client *encryption.ClientInstance) {
			protocol, err := vless.NewClient("7b4bb031-41b5-4d1d-b062-1ea0cab957c1", "", nil)
			if err != nil {
				results <- err
				return
			}
			for round := 0; round < rounds; round++ {
				client.RWLock.RLock()
				cached := len(client.Ticket) > 0 && time.Now().Before(client.Expire) && seconds != 0
				client.RWLock.RUnlock()
				conn, err := net.DialTimeout("tcp", os.Args[2], time.Second)
				if err != nil {
					results <- err
					return
				}
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				if roots != nil {
					secured := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12})
					if err := secured.Handshake(); err != nil {
						conn.Close()
						results <- err
						return
					}
					conn = secured
				}
				secured, err := client.Handshake(conn)
				if err != nil {
					conn.Close()
					results <- err
					return
				}
				packet, err := protocol.DialEarlyXUDPPacketConn(secured, target)
				if err != nil {
					conn.Close()
					results <- err
					return
				}
				_, err = packet.WriteTo(payload, target)
				var n int
				reply := make([]byte, 65536)
				if err == nil {
					n, _, err = packet.ReadFrom(reply)
				}
				packet.Close()
				if err != nil || !bytes.Equal(payload, reply[:n]) {
					results <- fmt.Errorf("worker=%d round=%d cached=%t payload=%d reply=%d error=%v", worker, round, cached, len(payload), n, err)
					return
				}
				fmt.Printf("same-peer short control worker=%d round=%d cached=%t bytes=%d passed\n", worker, round, cached, n)
			}
			results <- nil
		}(worker, client)
	}
	for range clients {
		if err := <-results; err != nil {
			fmt.Fprintln(os.Stderr, err)
			if result == nil {
				result = err
			}
		}
	}
	return true, result
}
