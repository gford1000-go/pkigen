package pkigen

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func verifyRSAKeyPair(pub *rsa.PublicKey, priv *rsa.PrivateKey, t *testing.T) {
	secretMessage := []byte("my secret message")
	label := []byte("my label")

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, secretMessage, label)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, label)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secretMessage, plaintext) {
		t.Errorf("Mismatch: expected '%s', received '%s'", secretMessage, plaintext)
	}
}

func verifyContentsOfBase64EncodedRSAKey(b *Base64EncodedRSAKey, t *testing.T) {
	pubKey, err := UnmarshalPublicKey(b)
	if err != nil {
		t.Fatal(err)
	}

	privKey, err := UnmarshalPrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}

	verifyRSAKeyPair(pubKey, privKey, t)
}

func TestGen(t *testing.T) {

	b, err := CreateEncodedRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	verifyContentsOfBase64EncodedRSAKey(b, t)
}
