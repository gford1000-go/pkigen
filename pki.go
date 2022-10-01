package pkigen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

var errNoPublicKey = errors.New("PrivateKey does not contain a PublicKey")
var errInvalidPrivateKeyMaterial = errors.New("invalid PrivateKey material")
var errInvalidPublicKeyMaterial = errors.New("invalid PublicKey material")

// Base64EncodedRSAKey stores details of RSA keys, as base64 url-encoded strings
type Base64EncodedRSAKey struct {
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
}

// CreateEncodedRSAKey returns a fully populated Base64EncodedRSAKey,
// where new keys are generated on each call using the specified number of bits
func CreateEncodedRSAKey(size int) (*Base64EncodedRSAKey, error) {

	// reader is defined in rand.go
	priv, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}
	return Marshal(priv)
}

// Marshal returns a Base64EncodedRSAKey from the specified key
func Marshal(priv *rsa.PrivateKey) (*Base64EncodedRSAKey, error) {
	b, err := MarshalPublicKey(priv)
	if err != nil {
		return nil, err
	}
	b.PrivateKey = marshalPrivateKey(priv)
	return b, nil
}

// MarshalPublicKey returns a Base64EncodedRSAKey that only
// contains the public key, taken from the supplied private key
func MarshalPublicKey(priv *rsa.PrivateKey) (*Base64EncodedRSAKey, error) {
	pub := &priv.PublicKey
	if pub == nil {
		return nil, errNoPublicKey
	}
	return &Base64EncodedRSAKey{
		PublicKey: marshalPublicKey(pub),
	}, nil
}

func marshalPublicKey(pub *rsa.PublicKey) string {
	return base64.URLEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(pub))
}

func marshalPrivateKey(priv *rsa.PrivateKey) string {
	return base64.URLEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(priv))
}

// UnmarshalPrivateKey returns the PrivateKey from the Base64EncodedRSAKey
func UnmarshalPrivateKey(b *Base64EncodedRSAKey) (*rsa.PrivateKey, error) {
	privBytes, err := base64.URLEncoding.DecodeString(b.PrivateKey)
	if err != nil {
		return nil, errInvalidPrivateKeyMaterial
	}
	return x509.ParsePKCS1PrivateKey(privBytes)
}

// UnmarshalPrivateKey returns the PublicKey from the Base64EncodedRSAKey
func UnmarshalPublicKey(b *Base64EncodedRSAKey) (*rsa.PublicKey, error) {
	return unmarshalPublicKey(b.PublicKey)
}

func unmarshalPublicKey(encS string) (*rsa.PublicKey, error) {
	pubBytes, err := base64.URLEncoding.DecodeString(encS)
	if err != nil {
		return nil, errInvalidPublicKeyMaterial
	}
	return x509.ParsePKCS1PublicKey(pubBytes)
}
