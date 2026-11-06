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

// A separate client implementation for repeated same-peer UDP batch checks.
func probe() error {
	if len(os.Args) != 9 {
		return fmt.Errorf("probe peer encryption ca targetA targetB targetV6 rounds")
	}
	parts := strings.Split(os.Args[3], ".")
	if len(parts) < 4 {
		return fmt.Errorf("bad encryption")
	}
	mode := uint32(0)
	if parts[1] == "xorpub" {
		mode = 1
	}
	if parts[1] == "random" {
		mode = 2
	}
	public, err := base64.RawURLEncoding.DecodeString(parts[len(parts)-1])
	if err != nil {
		return err
	}
	rounds, err := strconv.Atoi(os.Args[8])
	if err != nil {
		return err
	}
	errors := make(chan error, 2)
	for worker := 0; worker < 2; worker++ {
		go func(worker int) {
			client := &encryption.ClientInstance{}
			if err := client.Init([][]byte{public}, mode, 1, strings.Join(parts[3:len(parts)-1], ".")); err != nil {
				errors <- err
				return
			}
			protocol, err := vless.NewClient("7b4bb031-41b5-4d1d-b062-1ea0cab957c1", "", nil)
			if err != nil {
				errors <- err
				return
			}
			open := func(target M.Socksaddr) (net.PacketConn, error) {
				conn, err := net.DialTimeout("tcp", os.Args[2], time.Second)
				if err != nil {
					return nil, err
				}
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if os.Args[4] != "-" {
					roots := x509.NewCertPool()
					if !roots.AppendCertsFromPEM(read(os.Args[4])) {
						conn.Close()
						return nil, fmt.Errorf("bad CA")
					}
					secured := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12})
					if err = secured.Handshake(); err != nil {
						conn.Close()
						return nil, err
					}
					conn = secured
				}
				secured, err := client.Handshake(conn)
				if err != nil {
					conn.Close()
					return nil, err
				}
				packet, err := protocol.DialEarlyXUDPPacketConn(secured, target)
				if err != nil {
					conn.Close()
					return nil, err
				}
				return packet, nil
			}
			for round := 0; round < rounds; round++ {
				a, b, v6 := M.ParseSocksaddr(os.Args[5]), M.ParseSocksaddr(os.Args[6]), M.ParseSocksaddr(os.Args[7])
				main, err := open(a)
				if err != nil {
					errors <- err
					return
				}
				for index, target := range []M.Socksaddr{a, b, a} {
					payload := bytes.Repeat([]byte{byte(index)}, 1024+index)
					if _, err = main.WriteTo(payload, target); err != nil {
						break
					}
				}
				if err == nil {
					seen := [3]bool{}
					reply := make([]byte, 65536)
					for i := 0; i < 3; i++ {
						var n int
						n, _, err = main.ReadFrom(reply)
						if err != nil {
							break
						}
						index := int(reply[0])
						if index >= 3 || seen[index] || !bytes.Equal(reply[:n], bytes.Repeat([]byte{byte(index)}, 1024+index)) {
							err = fmt.Errorf("batch payload mismatch")
							break
						}
						seen[index] = true
					}
				}
				if err != nil {
					main.Close()
					errors <- fmt.Errorf("worker=%d round=%d batch: %w", worker, round, err)
					return
				}
				for _, target := range []M.Socksaddr{v6, M.ParseSocksaddr(net.JoinHostPort("localhost", strconv.Itoa(int(a.Port))))} {
					pc, e := open(target)
					if e != nil {
						err = e
						break
					}
					_, err = pc.WriteTo([]byte("control"), target)
					if err == nil {
						reply := make([]byte, 128)
						var n int
						n, _, err = pc.ReadFrom(reply)
						if err == nil && string(reply[:n]) != "control" {
							err = fmt.Errorf("single payload mismatch")
						}
					}
					pc.Close()
					if err != nil {
						break
					}
				}
				main.Close()
				if err != nil {
					errors <- fmt.Errorf("worker=%d round=%d extra lane: %w", worker, round, err)
					return
				}
			}
			errors <- nil
		}(worker)
	}
	for i := 0; i < 2; i++ {
		if err := <-errors; err != nil {
			return err
		}
	}
	fmt.Printf("Independent same-peer client: %d rounds, two workers, batched A/B/A, IPv6/domain lanes passed\n", rounds)
	return nil
}
