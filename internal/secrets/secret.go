package secrets

import (
	"errors"
	"fmt"
	"strings"

	"github.com/99designs/keyring"
)

var errMissingSecretKey = errors.New("missing secret key")

func SetSecret(key string, value []byte) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errMissingSecretKey
	}

	ring, err := openKeyringFunc()
	if err != nil {
		return err
	}

	if err := withOptionalKeyringLock(ring, true, func() error {
		return verifiedSet(ring, key, value, "secret")
	}); err != nil {
		return wrapKeychainError(fmt.Errorf("store secret: %w", err))
	}

	return nil
}

func GetSecret(key string) ([]byte, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, errMissingSecretKey
	}

	ring, err := openKeyringFunc()
	if err != nil {
		return nil, err
	}

	var item keyring.Item

	if err := withOptionalKeyringLock(ring, false, func() error {
		var getErr error

		item, getErr = ring.Get(key)
		if getErr != nil {
			return fmt.Errorf("get secret: %w", getErr)
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}

	return item.Data, nil
}

func DeleteSecret(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errMissingSecretKey
	}

	ring, err := openKeyringFunc()
	if err != nil {
		return err
	}

	if err := withOptionalKeyringLock(ring, true, func() error {
		if removeErr := ring.Remove(key); removeErr != nil {
			return fmt.Errorf("delete secret: %w", removeErr)
		}

		return nil
	}); err != nil {
		return wrapKeychainError(fmt.Errorf("delete secret: %w", err))
	}

	return nil
}
