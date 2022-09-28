package pkigen

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
)

type gcmEncryptedData struct {
	Key        []byte
	Nonce      []byte
	Ciphertext []byte
}

func gcmEncrypt(b []byte) (*gcmEncryptedData, error) {
	// reader defined in rand.go
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(reader, aesKey); err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &gcmEncryptedData{
		Key:        aesKey,
		Nonce:      nonce,
		Ciphertext: aesgcm.Seal(nil, nonce, b, nil),
	}, nil

}

func gcmDecrypt(d *gcmEncryptedData) ([]byte, error) {
	block, err := aes.NewCipher(d.Key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, d.Nonce, d.Ciphertext, nil)
}
