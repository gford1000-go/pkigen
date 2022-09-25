package pkigen

import (
	"bytes"
	"testing"
)

func TestGCM(t *testing.T) {

	var secret_message = []byte("Hello World!")

	d, err := gcmEncrypt(secret_message)
	if err != nil {
		t.Fatal(err)
	}

	b, err := gcmDecrypt(d)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(b, secret_message) {
		t.Errorf("Expected '%s', got '%s'", secret_message, b)
	}
}

func TestGCMKeyChange(t *testing.T) {

	var secret_message = []byte("Hello World!")

	d, err := gcmEncrypt(secret_message)
	if err != nil {
		t.Fatal(err)
	}

	d.Key = make([]byte, 32)
	_, err = gcmDecrypt(d)
	if err == nil {
		t.Fatal("Authentication error should have been returned")
	}
}

func TestGCMNonceChange(t *testing.T) {

	var secret_message = []byte("Hello World!")

	d, err := gcmEncrypt(secret_message)
	if err != nil {
		t.Fatal(err)
	}

	d.Nonce = make([]byte, 12)
	_, err = gcmDecrypt(d)
	if err == nil {
		t.Fatal("Authentication error should have been returned")
	}
}

func TestGCMCipherChange(t *testing.T) {

	var secret_message = []byte("Hello World!")

	d, err := gcmEncrypt(secret_message)
	if err != nil {
		t.Fatal(err)
	}

	d.Ciphertext[2] = d.Ciphertext[2] + 1

	_, err = gcmDecrypt(d)
	if err == nil {
		t.Fatal("Authentication error should have been returned")
	}
}
