package pkigen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

var OAEP_SHA256 = "OAEP_SHA256"
var GCM = "GCM"

var errInvalidEnvelopeAlgo = errors.New("invalid envelope algo")
var errInvalidDetailAlgo = errors.New("invalid symmetric algo")

// EncryptedRSAKey provides sufficient details to be able to decrypt the
// Base64EncodedRSAKey details in KeyDetail, provided the private key
// corresponding to EnvelopePublicKey is known
type EncryptedRSAKey struct {
	EnvelopePublicKey     string `json:"envelope_pk"`
	EnvelopeAlgo          string `json:"envelope_algo"`
	DetailEncyptionKey    string `json:"detail_encryption_key"`
	DetailEncryptionNonce string `json:"detail_encryption_nonce"`
	DetailAlgo            string `json:"detail_algo"`
	KeyDetail             string `json:"key_detail"`
}

// CreateEncryptedRSAKey creates a Base64EncodedRSAKey with keys using the
// specified bit size, where the Base64EncodedRSAKey is encrypted using the
// supplied public key.
// The Base64EncodedRSAKey is actually symmetrically encrypted using a one
// time random key and nonce, and it is the random key that is then
// envelope encrypted with the supplied public key.  This ensures that
// the process will work with different bit sizes.
func CreateEncryptedRSAKey(pubKey *rsa.PublicKey, size int) (*EncryptedRSAKey, error) {
	b, err := CreateEncodedRSAKey(size)
	if err != nil {
		return nil, err
	}

	return EncryptRSAKey(pubKey, b)
}

// EncryptRSAKey encrypts the provided Base64EncodedRSAKey using the
// supplied public key.
// The Base64EncodedRSAKey is actually symmetrically encrypted using a one
// time random key and nonce, and it is the random key that is then
// envelope encrypted with the supplied public key.  This ensures that
// the process will work with different bit sizes.
func EncryptRSAKey(pubKey *rsa.PublicKey, b *Base64EncodedRSAKey) (*EncryptedRSAKey, error) {
	jsonBytes, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}

	d, err := gcmEncrypt(jsonBytes)
	if err != nil {
		return nil, err
	}

	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, d.Key, nil)
	if err != nil {
		return nil, err
	}

	return &EncryptedRSAKey{
		EnvelopePublicKey:     marshalPublicKey(pubKey),
		EnvelopeAlgo:          OAEP_SHA256,
		DetailEncyptionKey:    base64.URLEncoding.EncodeToString(encryptedAESKey),
		DetailEncryptionNonce: base64.URLEncoding.EncodeToString(d.Nonce),
		DetailAlgo:            GCM,
		KeyDetail:             base64.URLEncoding.EncodeToString(d.Ciphertext),
	}, nil
}

// UnmarshalEnvelopePublicKey returns the public key that was used to encrypt the
// data in this instance, so that the corresponding private key can be identified
func (e *EncryptedRSAKey) UnmarshalEnvelopePublicKey() (*rsa.PublicKey, error) {
	return unmarshalPublicKey(e.EnvelopePublicKey)
}

// Unmarshal will return the Base64EncodedRSAKey, provided that the supplied
// private key matches the public key used for encryption, and the contents of
// EncryptedRSAKey have not been modified
func (e *EncryptedRSAKey) Unmarshal(privKey *rsa.PrivateKey) (*Base64EncodedRSAKey, error) {
	if e.EnvelopeAlgo != OAEP_SHA256 {
		return nil, errInvalidEnvelopeAlgo
	}
	if e.DetailAlgo != GCM {
		return nil, errInvalidDetailAlgo
	}

	encryptedASEKey, err := base64.URLEncoding.DecodeString(e.DetailEncyptionKey)
	if err != nil {
		return nil, err
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encryptedASEKey, nil)
	if err != nil {
		return nil, err
	}

	nonce, err := base64.URLEncoding.DecodeString(e.DetailEncryptionNonce)
	if err != nil {
		return nil, err
	}

	encryptedKeyDetail, err := base64.URLEncoding.DecodeString(e.KeyDetail)
	if err != nil {
		return nil, err
	}

	jsonBytes, err := gcmDecrypt(&gcmEncryptedData{
		Key:        aesKey,
		Nonce:      nonce,
		Ciphertext: encryptedKeyDetail,
	})
	if err != nil {
		return nil, err
	}

	b := &Base64EncodedRSAKey{}
	err = json.Unmarshal(jsonBytes, b)
	return b, err
}
