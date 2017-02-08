package plainsession

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Session struct {
	MaxAge     int64
	Values     map[string]string
	encryption string
	secretKey  string
	iv         []byte
}

func New(maxAge int64, secretKey string) (*Session, error) {
	if len(secretKey) != 32 {
		return nil, errors.New("secretKey must be a string that has 32 chars")
	}
	return &Session{
		MaxAge:    maxAge,
		Values:    map[string]string{},
		secretKey: secretKey,
		iv:        []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
	}, nil
}

func (s *Session) Set(k string, v string) {
	s.Values[k] = v
}

func (s *Session) Del(k string) {
	_, ok := s.Values[k]
	if ok {
		delete(s.Values, k)
	}
}

func (s *Session) Flush() {
	s.Values = map[string]string{}
	s.encryption = ""
}

func (s *Session) Get(k string) (string, bool) {
	v, e := s.Values[k]
	return v, e
}

func (s *Session) GetValues() string {
	kvs := []string{}
	for k, v := range s.Values {
		kvs = append(kvs, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(kvs, ";")
}

func (s *Session) GetEncryption() string {
	if s.encryption != "" {
		return s.encryption
	}
	plaintext := s.GetValues()
	plaintext = fmt.Sprintf("%s;%s", strconv.FormatInt(time.Now().UnixNano(), 10), plaintext)
	c, _ := aes.NewCipher([]byte(s.secretKey))
	cfb := cipher.NewCFBEncrypter(c, s.iv)
	ciphertext := make([]byte, len(plaintext))
	fmt.Println(plaintext)
	cfb.XORKeyStream(ciphertext, []byte(plaintext))
	s.encryption = fmt.Sprintf("%x", ciphertext)
	return s.encryption
}

func (s *Session) Descrpt(encryption string) error {
	ciphertext, e := hex.DecodeString(encryption)
	if e != nil {
		return e
	}
	block, _ := aes.NewCipher([]byte(s.secretKey))
	stream := cipher.NewCFBDecrypter(block, s.iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	plaintext := string(ciphertext)

	m := map[string]string{}
	ks := strings.Split(plaintext, ";")
	for _, item := range ks[1:] {
		kv := strings.Split(item, "=")
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		} else {
			return fmt.Errorf("invalid format: %s", item)
		}
	}
	s.Values = m
	s.encryption = encryption
	return nil
}
