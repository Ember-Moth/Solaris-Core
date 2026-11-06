package main

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	jls "github.com/metacubex/jls-tls"
	restls "github.com/metacubex/restls-client-go"
	shadow "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	reality "github.com/xtls/reality"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const password = "solaris-tls-patch-password"

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type invalidSigner struct {
	crypto.Signer
	empty bool
}

func (s invalidSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	if s.empty {
		return nil, nil
	}
	return make([]byte, 72), nil
}

type helloTamper struct{ net.Conn }

func (c helloTamper) Write(data []byte) (int, error) {
	copyData := append([]byte(nil), data...)
	for offset := 0; offset+5 <= len(copyData); {
		size := 5 + int(copyData[offset+3])<<8 + int(copyData[offset+4])
		if size > len(copyData)-offset {
			break
		}
		if copyData[offset] == 22 && size >= 43 && copyData[offset+5] == 2 {
			copyData[offset+11] ^= 1 // ServerHello random, after its handshake header/version.
		}
		offset += size
	}
	return c.Conn.Write(copyData)
}

// A test-only active peer with the real traffic key: alter Finished while
// retaining a valid record AEAD tag, so this specifically tests Finished MACs.
type finishedTamper struct {
	net.Conn
	secret    []byte
	suite     uint16
	sequence  uint64
	done      bool
	algorithm bool
}

type trafficLog struct{ conn *finishedTamper }

func (l trafficLog) Write(p []byte) (int, error) {
	fields := strings.Fields(string(p))
	if len(fields) == 3 && fields[0] == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
		key, err := hex.DecodeString(fields[2])
		must(err)
		l.conn.secret = key
	}
	return len(p), nil
}

func expand(secret []byte, h func() hash.Hash, label string, size int) []byte {
	label = "tls13 " + label
	info := append([]byte{byte(size >> 8), byte(size), byte(len(label))}, label...)
	info = append(info, 0)
	key := make([]byte, size)
	_, err := io.ReadFull(hkdf.Expand(h, secret, info), key)
	must(err)
	return key
}

func (c *finishedTamper) Write(data []byte) (int, error) {
	wire := append([]byte(nil), data...)
	for offset := 0; offset+5 <= len(wire); {
		size := 5 + int(wire[offset+3])<<8 + int(wire[offset+4])
		if size > len(wire)-offset {
			panic("reference server split an emitted TLS record")
		}
		record := wire[offset : offset+size]
		if record[0] == 22 && size >= 44 && record[5] == 2 {
			i := 44 + int(record[43])
			if i+2 > size {
				panic("invalid reference ServerHello")
			}
			c.suite = uint16(record[i])<<8 | uint16(record[i+1])
		}
		if record[0] == 23 && !c.done {
			var h func() hash.Hash = sha256.New
			keySize := 16
			if c.suite == 0x1302 {
				h = sha512.New384
				keySize = 32
			}
			if c.suite == 0x1303 {
				keySize = 32
			}
			key, nonce := expand(c.secret, h, "key", keySize), expand(c.secret, h, "iv", 12)
			for i := 0; i < 8; i++ {
				nonce[len(nonce)-1-i] ^= byte(c.sequence >> (8 * i))
			}
			var aead cipher.AEAD
			var err error
			if c.suite == 0x1303 {
				aead, err = chacha20poly1305.New(key)
			} else {
				var block cipher.Block
				block, err = aes.NewCipher(key)
				if err == nil {
					aead, err = cipher.NewGCM(block)
				}
			}
			must(err)
			plain, err := aead.Open(nil, nonce, record[5:], record[:5])
			must(err)
			end := len(plain) - 1
			for end >= 0 && plain[end] == 0 {
				end--
			}
			if end < 0 || plain[end] != 22 {
				panic("expected protected handshake message")
			}
			for i := 0; i+4 <= end; {
				n := 4 + int(plain[i+1])<<16 + int(plain[i+2])<<8 + int(plain[i+3])
				if n > end-i {
					panic("fragmented reference handshake message")
				}
				if (!c.algorithm && plain[i] == 20) || (c.algorithm && plain[i] == 15) {
					if c.algorithm {
						plain[i+4], plain[i+5] = 0xff, 0xff
					} else {
						plain[i+4] ^= 1
					}
					c.done = true
					break
				}
				i += n
			}
			if c.done {
				changed := aead.Seal(nil, nonce, plain, record[:5])
				copy(record[5:], changed)
			}
			c.sequence++
		}
		offset += size
	}
	return c.Conn.Write(wire)
}

type echoHandler struct{}

func (echoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, done N.CloseHandlerFunc) {
	_, err := io.Copy(conn, conn)
	conn.Close()
	if done != nil {
		done(err)
	}
}

func main() {
	if len(os.Args) != 3 {
		panic("certificate.pem key.pem")
	}
	certificate, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	must(err)
	jlsCertificate, err := jls.LoadX509KeyPair(os.Args[1], os.Args[2])
	must(err)
	var listeners []net.Listener
	var active sync.Map
	listen := func(handler func(net.Conn)) int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		must(err)
		listeners = append(listeners, listener)
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				active.Store(conn, true)
				go func() {
					defer active.Delete(conn)
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(10 * time.Second))
					handler(conn)
				}()
			}
		}()
		return listener.Addr().(*net.TCPAddr).Port
	}
	// Targets are real standard-library TLS servers and are loopback-only.
	target := func(version uint16, curve tls.CurveID) int {
		config := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: version, MaxVersion: version}
		if curve != 0 {
			config.CurvePreferences = []tls.CurveID{curve}
		}
		return listen(func(conn net.Conn) {
			secured := tls.Server(conn, config)
			if secured.Handshake() == nil {
				io.Copy(io.Discard, secured)
			}
		})
	}
	target13 := target(tls.VersionTLS13, 0)
	ports := map[string]any{}
	var ticketKey [32]byte
	for i := range ticketKey {
		ticketKey[i] = byte(i + 17)
	}
	for _, mode := range []string{"jls", "jls_bad_hello", "jls_bad_signature", "jls_empty_signature", "jls_bad_finished", "jls_bad_algorithm", "ordinary", "ordinary_bad_signature"} {
		config := &jls.Config{Certificates: []jls.Certificate{jlsCertificate}, MinVersion: jls.VersionTLS13, MaxVersion: jls.VersionTLS13}
		config.SetSessionTicketKeys([][32]byte{ticketKey})
		if mode != "ordinary" && mode != "ordinary_bad_signature" {
			config.JLSConfig = &jls.JLSConfig{Enable: true, Users: []jls.JLSUser{{Username: "user", Password: password}, {Username: "other", Password: password + "-other"}}}
		}
		if mode == "jls_bad_signature" || mode == "jls_empty_signature" || mode == "ordinary_bad_signature" {
			config.Certificates[0].PrivateKey = invalidSigner{config.Certificates[0].PrivateKey.(crypto.Signer), mode == "jls_empty_signature"}
		}
		ports[mode] = listen(func(conn net.Conn) {
			connectionConfig := config
			if mode == "jls_bad_hello" {
				conn = helloTamper{conn}
			}
			if mode == "jls_bad_finished" || mode == "jls_bad_algorithm" {
				wrapped := &finishedTamper{Conn: conn, algorithm: mode == "jls_bad_algorithm"}
				conn = wrapped
				connectionConfig = config.Clone()
				connectionConfig.KeyLogWriter = trafficLog{wrapped}
			}
			secured := jls.Server(conn, connectionConfig)
			if secured.Handshake() != nil {
				return
			}
			state := secured.ConnectionState()
			if config.JLSConfig != nil && state.JLS.Status != jls.JLSAuthenticated {
				panic("reference server accepted an unauthenticated JLS connection")
			}
			io.Copy(secured, secured)
		})
	}
	for name, spec := range map[string]struct {
		version uint16
		curve   tls.CurveID
	}{"restls13": {tls.VersionTLS13, 0}, "restls12_x25519": {tls.VersionTLS12, tls.X25519}, "restls12_p256": {tls.VersionTLS12, tls.CurveP256}, "restls12_p384": {tls.VersionTLS12, tls.CurveP384}} {
		upstream := target(spec.version, spec.curve)
		config := &restls.RestlsServerConfig{ServerHostname: fmt.Sprintf("127.0.0.1:%d", upstream), Password: password, RestlsScript: "100", MinRecordLen: 15}
		ports[name] = listen(func(conn net.Conn) {
			secured, err := restls.RestlsServer(context.Background(), conn, config)
			if err == nil {
				defer secured.Close()
				_, err = io.Copy(secured, secured)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			}
		})
	}
	var private [32]byte
	for i := range private {
		private[i] = byte(i + 1)
	}
	key, err := ecdh.X25519().NewPrivateKey(private[:])
	must(err)
	ports["reality_public_key"] = hex.EncodeToString(key.PublicKey().Bytes())
	realityConfig := &reality.Config{Type: "tcp", Dest: fmt.Sprintf("127.0.0.1:%d", target13), PrivateKey: key,
		ServerNames: map[string]bool{"localhost": true}, ShortIds: map[[8]byte]bool{{1, 2, 3, 4, 5, 6, 7, 8}: true}, MaxTimeDiff: time.Minute,
		DialContext: (&net.Dialer{}).DialContext}
	reality.DetectPostHandshakeRecordsLens(realityConfig)
	until := time.Now().Add(5 * time.Second)
	for {
		value, _ := reality.GlobalPostHandshakeRecordsLens.Load(realityConfig.Dest + " localhost 0")
		if _, ready := value.([]int); ready {
			break
		}
		if time.Now().After(until) {
			panic("REALITY target probe did not settle")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ports["reality"] = listen(func(conn net.Conn) {
		secured, err := reality.Server(context.Background(), conn, realityConfig)
		if err == nil {
			defer secured.Close()
			io.Copy(secured, secured)
		}
	})
	service, err := shadow.NewService(shadow.ServiceConfig{Version: 3, Users: []shadow.User{{Name: "test", Password: password}}, StrictMode: true,
		Handshake: shadow.HandshakeConfig{Server: M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", target13)), Dialer: N.SystemDialer}, Handler: echoHandler{}, Logger: logger.NOP()})
	must(err)
	ports["shadowtls3"] = listen(func(conn net.Conn) {
		_ = service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), M.Socksaddr{}, nil)
	})
	encoded, err := json.Marshal(ports)
	must(err)
	fmt.Println(string(encoded))
	io.Copy(io.Discard, os.Stdin)
	for _, listener := range listeners {
		listener.Close()
	}
	active.Range(func(key, _ any) bool { key.(net.Conn).Close(); return true })
}
