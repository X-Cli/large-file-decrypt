package decrypt

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"path"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestDecrypt1(t *testing.T) {
	tmpdir := t.TempDir()

	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	expectedContent := []byte("Geronimo!")
	encryptedContent, err := box.SealAnonymous(nil, expectedContent, pubKey, rand.Reader)
	if err != nil {
		t.Fatalf("failed to encrypt message: %v", err)
	}

	encryptedFilePath := path.Join(tmpdir, "encryptedFile")
	if err := ioutil.WriteFile(encryptedFilePath, encryptedContent, 0o600); err != nil {
		t.Fatalf("failed to initialize encrypted file: %v", err)
	}

	decryptedFilePath := path.Join(tmpdir, "decryptedFile")
	if err := DecryptFile(encryptedFilePath, decryptedFilePath, pubKey, privKey); err != nil {
		t.Fatalf("failed to decrypt file: %v", err)
	}

	decryptedContent, err := ioutil.ReadFile(decryptedFilePath)
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(expectedContent, decryptedContent) {
		t.Fatalf("mismatched content: expected %v, found %v", expectedContent, decryptedContent)
	}
}
