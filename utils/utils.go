package utils

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/sys/unix"
)

func CreatePrivateCopyOf(inputPath, tempDir string) (privateFile *os.File, errStack *multierror.Error) {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to open file %q: %w", inputPath, err))
		return
	}
	defer func() {
		if err := inputFile.Close(); err != nil {
			errStack = multierror.Append(errStack, fmt.Errorf("failed to close file %q: %w", inputPath, err))
		}
	}()

	privateFileFd, err := unix.Open(tempDir, unix.O_RDWR|unix.O_TMPFILE, 0o600)
	if err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to open private file: %w", err))
		return
	}

	privateFile = os.NewFile(uintptr(privateFileFd), "")
	defer func() {
		if errStack.ErrorOrNil() != nil {
			if err := privateFile.Close(); err != nil {
				errStack = multierror.Append(errStack, fmt.Errorf("failed to close private copy: %w", err))
			}
		}
	}()

	if err := unix.IoctlFileClone(int(privateFile.Fd()), int(inputFile.Fd())); err != nil {
		if err != syscall.EOPNOTSUPP && err != syscall.EINVAL {
			errStack = multierror.Append(errStack, fmt.Errorf("failed to clone file: %w", err))
			return
		}
		if _, err := io.Copy(privateFile, inputFile); err != nil {
			errStack = multierror.Append(errStack, fmt.Errorf("failed to copy file: %w", err))
			return
		}
	}
	return
}

func GetDataFromFile(privateEncryptedFile *os.File) (data []byte, err error) {
	fs, err := privateEncryptedFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat(2) private copy of encrypted file: %w", err)
	}
	data, err = syscall.Mmap(int(privateEncryptedFile.Fd()), 0, int(fs.Size()), syscall.PROT_WRITE|syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap(2) private copy of encrypted file: %w", err)
	}
	return data, nil
}

func CreatePrivateFile(tempDir string, size int64) (*os.File, error) {
	privateFileFd, err := unix.Open(tempDir, unix.O_RDWR|unix.O_TMPFILE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to create private file: %w", err)
	}
	privateFile := os.NewFile(uintptr(privateFileFd), "")

	if err := syscall.Fallocate(int(privateFile.Fd()), 0, 0, size); err != nil {
		var errStack error = err
		if err := privateFile.Close(); err != nil {
			errStack = multierror.Append(errStack, err)
		}
		return nil, errStack
	}
	return privateFile, nil
}

func PublishFile(privateDecryptedFile *os.File, outputPath string) (errStack *multierror.Error) {
	if err := unix.Linkat(int(privateDecryptedFile.Fd()), "", 0, outputPath, unix.AT_EMPTY_PATH); err == nil {
		return
	} else if err != syscall.ENOENT {
		// ENOENT is returned if CAP_DAC_READ_SEARCH is not effective
		errStack = multierror.Append(errStack, fmt.Errorf("failed to call linkat: %w", err))
		return
	}
	outputFile, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to create output file: %w", err))
		return
	}
	defer func() {
		if err := outputFile.Close(); err != nil {
			errStack = multierror.Append(errStack, fmt.Errorf("failed to close file %q: %w", outputPath, err))
		}
	}()
	if err := unix.IoctlFileClone(int(outputFile.Fd()), int(privateDecryptedFile.Fd())); err == nil {
		return
	} else if err != syscall.EOPNOTSUPP && err != syscall.EINVAL {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to clone file %w", err))
		return
	}
	if _, err := io.Copy(outputFile, privateDecryptedFile); err != nil {
		errStack = multierror.Append(errStack, fmt.Errorf("failed to copy into public decrypted file: %w", err))
		return
	}
	return
}
