package encrypt

import (
	"crypto/rand"
	"fmt"
	"io"
	"path/filepath"
	"syscall"

	"github.com/X-Cli/large-file-decrypt/utils"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sys/unix"
)

func EncryptFile(inputPath, outputPath string, pubKey *[32]byte) error {
	return encryptFile(inputPath, outputPath, pubKey, rand.Reader).ErrorOrNil()
}

func encryptFile(inputPath, outputPath string, pubKey *[32]byte, cryptoReader io.Reader) (errStack *multierror.Error) {
	inputTempDir := filepath.Dir(inputPath)

	privateClearFile, errs := utils.CreatePrivateCopyOf(inputPath, inputTempDir)
	if errs.ErrorOrNil() != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to acquire a private copy of %q: %w", inputPath, errs))
		return
	}
	privateClearFileClosed := false
	defer func() {
		if !privateClearFileClosed {
			if err := privateClearFile.Close(); err != nil {
				errStack = multierror.Append(errStack, fmt.Errorf("failed to close private copy of %q: %w", inputPath, err))
			}
		}
	}()

	clearData, err := utils.GetDataFromFile(privateClearFile)
	if err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to get data from private copy: %w", err))
		return
	}
	clearDataFreed := false
	defer func() {
		if !clearDataFreed {
			if err := syscall.Munmap(clearData); err != nil {
				errStack = multierror.Append(errStack, fmt.Errorf("failed to munmap clear data: %w", err))
			}
		}
	}()

	outputTempDir := filepath.Dir(outputPath)
	encryptedSize := len(clearData) + box.AnonymousOverhead
	privateEncryptedFile, err := utils.CreatePrivateFile(outputTempDir, int64(encryptedSize))
	if err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to create private encrypted file: %w", err))
		return
	}
	defer func() {
		if err := privateEncryptedFile.Close(); err != nil {
			errStack = multierror.Append(errStack, fmt.Errorf("failed to close private encrypted file: %w", err))
		}
	}()

	encryptedData, err := utils.GetDataFromFile(privateEncryptedFile)
	if err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to get data from encrypted file: %w", err))
		return
	}
	defer func() {
		if err := syscall.Munmap(encryptedData); err != nil {
			errStack = multierror.Append(errStack, fmt.Errorf("failed to release encrypted data: %w", err))
		}
	}()

	if _, err := box.SealAnonymous(encryptedData[:0], clearData, pubKey, cryptoReader); err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to seal data: %w", err))
		return
	}
	if err := unix.Msync(encryptedData, unix.MS_SYNC); err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to flush encrypted data on disk: %w", err))
		return
	}

	// Releasing private clear text resources since they are no longer needed and they may occupy resources if file clone was not possible
	clearDataFreed = true
	if err := syscall.Munmap(clearData); err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to get data from private copy: %w", err))
		return
	}
	privateClearFileClosed = true
	if err := privateClearFile.Close(); err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to close private copy of %q: %w", inputPath, err))
		return
	}

	if err := utils.PublishFile(privateEncryptedFile, outputPath); err.ErrorOrNil() != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to publish encrypted file: %w", err))
		return
	}
	return

}
