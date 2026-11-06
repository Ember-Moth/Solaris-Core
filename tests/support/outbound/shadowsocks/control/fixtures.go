package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sagernet/sing-shadowsocks"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"lukechampine.com/blake3"
)

func fixtureKey(method int) []byte {
	length := 32
	if method == 0 || method == 3 {
		length = 16
	}
	if method >= 3 {
		return bytes.Repeat([]byte{73}, length)
	}
	return shadowsocks.Key([]byte("solaris-independent-peer"), length)
}

func fixtureAEAD(method int, salt []byte) cipher.AEAD {
	key := fixtureKey(method)
	subkey := make([]byte, len(key))
	if method >= 3 {
		blake3.DeriveKey(subkey, "shadowsocks 2022 session subkey", append(key, salt...))
	} else if _, err := io.ReadFull(hkdf.New(sha1.New, key, salt, []byte("ss-subkey")), subkey); err != nil {
		panic(err)
	}
	if method == 2 {
		aead, err := chacha20poly1305.New(subkey)
		if err != nil {
			panic(err)
		}
		return aead
	}
	block, err := aes.NewCipher(subkey)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

func streamFixture(method, variant int) []byte {
	key := fixtureKey(method)
	salt := bytes.Repeat([]byte{byte(99 + variant)}, len(key))
	aead := fixtureAEAD(method, salt)
	nonce := make([]byte, 12)
	payload := []byte("hello")
	if variant == 8 {
		payload = nil
	}
	if variant == 9 {
		size := 16383
		if method >= 3 {
			size = 65535
		}
		payload = bytes.Repeat([]byte{0x5a}, size)
	}
	var header []byte
	if method >= 3 {
		header = make([]byte, 11+len(key))
		header[0] = 1
		stamp := uint64(1700000000)
		if variant == 4 {
			stamp += 31
		}
		if variant == 7 {
			stamp += 30
		}
		binary.BigEndian.PutUint64(header[1:], stamp)
		copy(header[9:], bytes.Repeat([]byte{0x42}, len(key)))
		if variant == 3 {
			header[0] = 0
		}
		if variant == 5 {
			header[9] ^= 1
		}
	} else {
		header = make([]byte, 2)
	}
	binary.BigEndian.PutUint16(header[len(header)-2:], uint16(len(payload)))
	if variant == 6 {
		binary.BigEndian.PutUint16(header[len(header)-2:], 65535)
	}
	result := append(salt, aead.Seal(nil, nonce, header, nil)...)
	nonce[0]++
	result = append(result, aead.Seal(nil, nonce, payload, nil)...)
	if variant == 1 {
		result[len(result)-1] ^= 1
	}
	if variant == 2 {
		result = result[:len(result)-1]
	}
	return result
}

func generateFixtures(directory string) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		panic(err)
	}
	for method := 0; method < 5; method++ {
		for variant := 0; variant < 10; variant++ {
			path := filepath.Join(directory, fmt.Sprintf("stream-%d-%d.bin", method, variant))
			if err := os.WriteFile(path, streamFixture(method, variant), 0600); err != nil {
				panic(err)
			}
		}
		for variant := 0; variant < 19; variant++ {
			path := filepath.Join(directory, fmt.Sprintf("packet-%d-%d.bin", method, variant))
			if err := os.WriteFile(path, packetFixture(method, variant), 0600); err != nil {
				panic(err)
			}
		}
	}
}

func packetFixture(method, variant int) []byte {
	address := []byte{1, 127, 0, 0, 1, 1, 187}
	if variant == 6 {
		address[0] = 9
	}
	if variant == 15 {
		address = append([]byte{3, 11}, []byte("example.com")...)
		address = append(address, 1, 187)
	}
	payload := []byte("hello")
	if variant == 16 {
		payload = nil
	}
	if variant == 17 {
		payload = bytes.Repeat([]byte{0x5a}, 65000)
	}
	var prefix, plain, nonce []byte
	var aead cipher.AEAD
	key := fixtureKey(method)
	if method < 3 {
		prefix = bytes.Repeat([]byte{byte(99 + variant)}, len(key))
		nonce = make([]byte, 12)
		aead = fixtureAEAD(method, prefix)
	} else {
		prefix = make([]byte, 16)
		copy(prefix, []byte("server-0"))
		if variant == 7 {
			prefix[7] = '1'
		}
		if variant == 8 {
			prefix[7] = '2'
		}
		packet := uint64(10)
		if variant >= 1 && variant <= 6 || variant >= 13 {
			packet = 11
		}
		if variant == 9 {
			packet = 2048
		}
		if variant == 11 || variant == 12 {
			packet = 2047
		}
		binary.BigEndian.PutUint64(prefix[8:], packet)
		aead = fixtureAEAD(method, prefix[:8])
		nonce = append([]byte(nil), prefix[4:]...)
		plain = make([]byte, 19)
		plain[0] = 1
		if variant == 2 {
			plain[0] = 0
		}
		stamp := uint64(1700000000)
		if variant == 3 {
			stamp += 31
		}
		binary.BigEndian.PutUint64(plain[1:], stamp)
		copy(plain[9:], bytes.Repeat([]byte{0x42}, 8))
		if variant == 4 {
			plain[9] ^= 1
		}
		if variant == 5 {
			plain[17] = 0xff
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		block.Encrypt(prefix, prefix)
	}
	plain = append(plain, address...)
	plain = append(plain, payload...)
	result := append(prefix, aead.Seal(nil, nonce, plain, nil)...)
	if variant == 1 {
		result[len(result)-1] ^= 1
	}
	if variant == 13 {
		result = result[:len(result)-1]
	}
	return result
}
