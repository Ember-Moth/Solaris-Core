package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xtls/xray-core/proxy/vless/encryption"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte    { b, err := os.ReadFile(path); must(err); return b }
func save(path string, b []byte) { must(os.WriteFile(path, b, 0600)) }
func path(root, name string, id int) string {
	return filepath.Join(root, fmt.Sprintf("%s-%d.bin", name, id))
}
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*17 + 29)
	}
	return b
}
func rawPattern() []byte {
	b := make([]byte, 0, 87)
	for i := 0; i < 3; i++ {
		b = append(b, 23, 3, 3, 0, 24)
		b = append(b, pattern(24)...)
	}
	return b
}

type memoryConn struct {
	input  *bytes.Reader
	output bytes.Buffer
}

func (c *memoryConn) Read(b []byte) (int, error)       { return c.input.Read(b) }
func (c *memoryConn) Write(b []byte) (int, error)      { return c.output.Write(b) }
func (c *memoryConn) Close() error                     { return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }
func verify(c *encryption.CommonConn) {
	b := make([]byte, 20003)
	_, err := io.ReadFull(c, b)
	must(err)
	if !bytes.Equal(b, pattern(20003)) {
		panic("client plaintext mismatch")
	}
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "probe" {
		must(probe())
		return
	}
	if len(os.Args) != 3 {
		panic("prepare|fixtures directory")
	}
	root := os.Args[2]
	private := make([]byte, 32)
	for i := range private {
		private[i] = byte(i + 1)
	}
	xkey, err := ecdh.X25519().NewPrivateKey(private)
	must(err)
	public := base64.RawURLEncoding.EncodeToString(xkey.PublicKey().Bytes())
	if os.Args[1] == "prepare" {
		for id := 0; id < 6; id++ {
			mode := []string{"native", "xorpub", "random"}[id%3]
			config := "mlkem768x25519plus." + mode + ".0rtt.100-35-35.100-0-0.100-37-37." + public
			save(path(root, "config", id), []byte(config))
		}
		return
	}
	if os.Args[1] != "fixtures" {
		panic("unknown operation")
	}
	servers := make([]*encryption.ServerInstance, 6)
	streams := make([]*encryption.CommonConn, 6)
	connections := make([]*memoryConn, 6)
	for id := 0; id < 6; id++ {
		server := &encryption.ServerInstance{}
		must(server.Init([][]byte{private}, uint32(id%3), 120, 120, "100-35-35"))
		defer server.Close()
		hello := read(path(root, "hello", id))
		conn := &memoryConn{input: bytes.NewReader(hello)}
		stream, err := server.Handshake(conn, nil)
		must(err)
		if stream.UseAES != (id < 3) || len(stream.PreWrite) != 0 {
			panic("wrong negotiated cipher/handshake")
		}
		servers[id], streams[id], connections[id] = server, stream, conn
		_, err = stream.Write(pattern(20003))
		must(err)
		save(path(root, "response", id), conn.output.Bytes())
		// Authenticated, invalid padding length: exercise validation after AEAD.
		badLength := append([]byte(nil), conn.output.Bytes()...)
		nonce := make([]byte, 12)
		nonce[11] = 2
		copy(badLength[1168:1186], stream.AEAD.Seal(nil, nonce, []byte{0, 16}, nil))
		save(path(root, "bad-length", id), badLength)
		// Authenticate an all-zero PFS X25519 point under the genuine NFS key.
		pub := append([]byte(nil), hello[16:48]...)
		if id%3 != 0 {
			encryption.NewCTR(xkey.PublicKey().Bytes(), hello[:16]).XORKeyStream(pub, pub)
		}
		clientPublic, err := ecdh.X25519().NewPublicKey(pub)
		must(err)
		shared, err := xkey.ECDH(clientPublic)
		must(err)
		nfs := encryption.NewAEAD(hello[:16], shared, id < 3)
		pfs, err := nfs.Open(nil, encryption.MaxNonce, conn.output.Bytes()[:1136], nil)
		must(err)
		clear(pfs[1088:1120])
		badPoint := append([]byte(nil), conn.output.Bytes()...)
		copy(badPoint, nfs.Seal(nil, encryption.MaxNonce, pfs, nil))
		save(path(root, "bad-point", id), badPoint)
		// Independent counter-wrap/rekey records, including masked headers.
		united := pattern(96)
		raw := &memoryConn{input: bytes.NewReader(nil)}
		records := encryption.NewCommonConn(raw, id < 3)
		records.UnitedKey = united
		records.AEAD = encryption.NewAEAD([]byte("record-test"), united, id < 3)
		copy(records.AEAD.Nonce[:], encryption.MaxNonce)
		records.AEAD.Nonce[11] = 254
		if id%3 == 2 {
			records.Conn = encryption.NewXorConn(raw, encryption.NewCTR(united, pattern(16)), nil, 0, 0)
		}
		for i := 0; i < 3; i++ {
			_, err = records.Write(pattern(8))
			must(err)
		}
		save(path(root, "rekey", id), raw.output.Bytes())
		before := conn.output.Len()
		_, err = stream.Conn.Write(rawPattern())
		must(err)
		save(path(root, "raw-response", id), conn.output.Bytes()[before:])
	}
	input := bufio.NewReader(os.Stdin)
	fmt.Println("FULL_READY")
	line, err := input.ReadString('\n')
	must(err)
	if strings.TrimSpace(line) != "resume" {
		panic("expected resume")
	}
	for id := 0; id < 6; id++ {
		connections[id].input = bytes.NewReader(read(path(root, "records", id)))
		verify(streams[id])
		connections[id].input = bytes.NewReader(read(path(root, "raw-request", id)))
		rawReply := make([]byte, 87)
		_, err = io.ReadFull(streams[id].Conn, rawReply)
		must(err)
		if !bytes.Equal(rawReply, rawPattern()) {
			panic("raw client stream mismatch")
		}
		hello := read(path(root, "resume", id))
		conn := &memoryConn{input: bytes.NewReader(hello)}
		stream, err := servers[id].Handshake(conn, nil)
		must(err)
		if len(stream.PreWrite) != 16 {
			panic("expected actual 0-RTT resumption")
		}
		verify(stream)
		_, err = stream.Write(pattern(20003))
		must(err)
		save(path(root, "resumed-response", id), conn.output.Bytes())
		// Same client NFS key and ticket must not be accepted twice by the peer.
		_, err = servers[id].Handshake(&memoryConn{input: bytes.NewReader(hello)}, nil)
		if err == nil {
			panic("peer accepted a replayed resumed request")
		}
	}
	fmt.Println("RESUME_READY")
	line, err = input.ReadString('\n')
	must(err)
	if strings.TrimSpace(line) != "done" {
		panic("expected done")
	}
	fmt.Println("Independent Xray full/resumed handshake, records, replay and rekey fixtures passed")
}
