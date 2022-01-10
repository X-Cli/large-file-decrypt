package encrypt

import (
	"bytes"
	"io/ioutil"
	"path"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestEncrypt(t *testing.T) {
	tmpdir := t.TempDir()

	var constantRandom [512]byte
	randReader := bytes.NewBuffer(constantRandom[:])

	clearFile := path.Join(tmpdir, "clear")
	encryptedFile := path.Join(tmpdir, "encrypted")

	clearText := []byte("Geronimo!")
	if err := ioutil.WriteFile(clearFile, clearText, 0o600); err != nil {
		t.Fatalf("failed to write cleartext file: %v", err)
	}

	pubKey, _, err := box.GenerateKey(randReader)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	if err := encryptFile(clearFile, encryptedFile, pubKey, randReader); err != nil {
		t.Fatalf("failed to encrypt file: %v", err)
	}

	cipherText, err := ioutil.ReadFile(encryptedFile)
	if err != nil {
		t.Fatalf("failed to read encrypted file: %v", err)
	}

	expectedCiphertext := []byte{47, 229, 125, 163, 71, 205, 98, 67, 21, 40, 218, 172, 95, 187, 41, 7, 48, 255, 246, 132, 175, 196, 207, 194, 237, 144, 153, 95, 88, 203, 59, 116, 83, 218, 223, 164, 117, 110, 80, 197, 138, 128, 169, 16, 149, 74, 20, 245, 10, 169, 53, 61, 119, 218, 240, 50, 92}
	if !bytes.Equal(expectedCiphertext, cipherText) {
		t.Fatalf("unexpected ciphertext: expected %v; found %v", expectedCiphertext, cipherText)
	}
}
