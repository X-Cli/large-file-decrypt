package decrypt

import (
	"errors"
	"fmt"
	"path/filepath"
	"syscall"

	"github.com/X-Cli/large-file-decrypt/utils"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sys/unix"
)

func DecryptFile(inputPath, outputPath string, pubKey, privKey *[32]byte) error {
	return decryptFile(inputPath, outputPath, pubKey, privKey).ErrorOrNil()
}

func decryptFile(inputPath, outputPath string, pubKey, privKey *[32]byte) (errStack *multierror.Error) {
	inputTempDir := filepath.Dir(inputPath)
	privateEncryptedFile, errs := utils.CreatePrivateCopyOf(inputPath, inputTempDir)
	if errs.ErrorOrNil() != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to create the private copy of the encrypted file: %w", errs))
		return
	}
	privateEncryptedFileClosed := false
	defer func() {
		if !privateEncryptedFileClosed {
			if err := privateEncryptedFile.Close(); err != nil {
				errStack = multierror.Append(errStack, fmt.Errorf("failed to close private copy of encrypted file: %w", err))
			}
		}
	}()

	encryptedData, err := utils.GetDataFromFile(privateEncryptedFile)
	if err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to get encrypted data: %w", err))
		return
	}
	privateEncryptedDataFreed := false
	defer func() {
		if !privateEncryptedDataFreed {
			if err := syscall.Munmap(encryptedData); err != nil {
				errStack = multierror.Append(errStack, fmt.Errorf("failed to munmap encrypted data: %w", err))
			}
		}
	}()

	decryptedSize := len(encryptedData) - box.AnonymousOverhead
	outputTempDir := filepath.Dir(outputPath)
	privateDecryptedFile, err := utils.CreatePrivateFile(outputTempDir, int64(decryptedSize))
	if err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to create private decrypted file: %w", err))
		return
	}
	defer func() {
		if err := privateDecryptedFile.Close(); err != nil {
			errStack = multierror.Append(errStack, fmt.Errorf("failed to close private decrypted file: %w", err))
		}
	}()

	decryptedData, err := utils.GetDataFromFile(privateDecryptedFile)
	if err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to mmap decrypted file: %w", err))
		return
	}
	defer func() {
		if err := syscall.Munmap(decryptedData); err != nil {
			errStack = multierror.Append(errStack, fmt.Errorf("failed to munmap decrypted data: %w", err))
		}
	}()

	if _, ok := box.OpenAnonymous(decryptedData[:0], encryptedData, pubKey, privKey); !ok {
		errStack = multierror.Append(errStack, errors.New("failed to decrypt file"))
		return
	}

	if err := unix.Msync(decryptedData, unix.MS_SYNC); err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to flush changes to disk: %w", err))
		return
	}

	// Since in the worst case, we can only copy the private decrypted file to the public file, we release the private encrypted file now, so that the algorithm only uses a maximum of 3 times the size of the encrypted file
	privateEncryptedDataFreed = true
	if err := syscall.Munmap(encryptedData); err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to munmap encrypted data: %w", err))
		return
	}
	privateEncryptedFileClosed = true
	if err := privateEncryptedFile.Close(); err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to close private copy of encrypted file: %w", err))
		return
	}

	if err := utils.PublishFile(privateDecryptedFile, outputPath).ErrorOrNil(); err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to publish decrypted file: %w", err))
		return
	}
	return
}
