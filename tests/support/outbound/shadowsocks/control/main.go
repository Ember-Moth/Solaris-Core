package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "fixtures" {
		generateFixtures(os.Args[2])
		return
	}
	if len(os.Args) != 6 {
		panic("server password ipv4-destination ipv6-destination mode")
	}
	method, err := shadowaead.New("aes-128-gcm", nil, os.Args[2])
	if err != nil {
		panic(err)
	}
	conn, err := net.Dial("udp", os.Args[1])
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	packet := method.DialPacketConn(conn)
	targets := []string{os.Args[3], os.Args[4]}
	if os.Args[5] == "fresh-v6" {
		targets = targets[1:]
	}
	for index, target := range targets {
		address, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			panic(err)
		}
		var destination net.Addr = address
		if os.Args[5] == "domain" && index == 1 {
			destination = M.ParseSocksaddr(target)
		}
		payload := []byte("independent same-peer control")
		if _, err = packet.WriteTo(payload, destination); err != nil {
			panic(err)
		}
		packet.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		result := make([]byte, 1024)
		n, source, err := packet.ReadFrom(result)
		if (os.Args[5] == "mixed" || os.Args[5] == "domain") && index == 1 {
			if err == nil {
				if !bytes.Equal(result[:n], payload) || source.String() != target {
					panic("control echo mismatch")
				}
				fmt.Println("independent sing-shadowsocks: same peer supports second target:", target)
				continue
			}
			if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
				panic(err)
			}
			fmt.Println("independent sing-shadowsocks: same peer drops second target on one UDP mapping:", target)
		} else {
			if err != nil {
				panic(err)
			}
			if !bytes.Equal(result[:n], payload) || source.String() != target {
				panic("control echo mismatch")
			}
			fmt.Println("independent sing-shadowsocks: echo passed", target)
		}
	}
}
