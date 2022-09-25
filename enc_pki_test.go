package pkigen

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestEnc(t *testing.T) {

	// Generate my own personal one time key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Ask for data encrypted with my one time key pair
	e, err := CreateEncryptedRSAKey(&privKey.PublicKey, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal using my one time private key
	b, err := e.Unmarshal(privKey)
	if err != nil {
		t.Fatal(err)
	}

	// Demonstrate that the unencrypted data is valid
	verifyContentsOfBase64EncodedRSAKey(b, t)
}

func TestEncPubKey(t *testing.T) {

	// Generate my own personal one time key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Ask for data encrypted with my one time key pair
	e, err := CreateEncryptedRSAKey(&privKey.PublicKey, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pubKey, err := e.UnmarshalEnvelopePublicKey()
	if err != nil {
		t.Fatal(err)
	}

	// Demonstrate that the returned public key works
	verifyRSAKeyPair(pubKey, privKey, t)
}
