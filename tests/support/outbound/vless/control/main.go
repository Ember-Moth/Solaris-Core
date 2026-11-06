package main

import (
    "fmt"
    "io"
    "net"
    "os"
    "time"

    "github.com/sagernet/sing-vmess/vless"
    M "github.com/sagernet/sing/common/metadata"
)

func main() {
    if err := run(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
func run() error {
    if len(os.Args) != 4 && len(os.Args) != 5 { return fmt.Errorf("peer uuid target [second-target] required") }
    conn, err := net.DialTimeout("tcp", os.Args[1], time.Second)
    if err != nil { return err }; defer conn.Close()
    client, err := vless.NewClient(os.Args[2], "", nil)
    if err != nil { return err }
    target := M.ParseSocksaddr(os.Args[3])
    packet, err := client.DialEarlyXUDPPacketConn(conn, target)
    if err != nil { return err }
    // Verify normal data on this exact peer before probing zero-length data.
    if _, err = packet.WriteTo([]byte("control"), target); err != nil { return err }
    conn.SetReadDeadline(time.Now().Add(time.Second))
    data := make([]byte, 1024)
    n, _, err := packet.ReadFrom(data)
    if err != nil || string(data[:n]) != "control" { return fmt.Errorf("normal control: %q %v", data[:n], err) }
    payload := []byte(nil)
    label := "empty"
    if len(os.Args) == 5 { target = M.ParseSocksaddr(os.Args[4]); payload = []byte("mixed"); label = "mixed-address" }
    if _, err = packet.WriteTo(payload, target); err != nil { return err }
    conn.SetReadDeadline(time.Now().Add(250*time.Millisecond))
    n, _, err = packet.ReadFrom(data)
    if err == nil && string(data[:n]) == string(payload) { fmt.Printf("same-peer independent client: %s XUDP supported\n", label); return nil }
    if timeout, ok := err.(net.Error); (!ok || !timeout.Timeout()) && err != io.EOF { return fmt.Errorf("%s control: %d %v", label, n, err) }
    fmt.Printf("same-peer independent client: normal reply passed, %s XUDP unavailable (%v)\n", label, err)
    return nil
}
