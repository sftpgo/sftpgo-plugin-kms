// Copyright (C) 2021 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package secret

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"

	"github.com/sftpgo/sdk/kms"
	"gocloud.dev/secrets/localsecrets"
	"golang.org/x/crypto/hkdf"
)

var (
	errWrongSecretStatus = errors.New("wrong secret status")
	errInvalidSecret     = errors.New("invalid secret")
)

// LocalSecret defines a SecretProvider that use a locally provided symmetric key
type LocalSecret struct {
	kms.BaseSecret
	MasterKey string
}

// GetPayload returns the secret's payload
func (s *LocalSecret) GetPayload() string {
	return s.Payload
}

// GetKey returns the secret's key
func (s *LocalSecret) GetKey() string {
	return s.Key
}

// GetMode returns the encryption mode
func (s *LocalSecret) GetMode() int {
	return s.Mode
}

func (s *LocalSecret) Encrypt() error {
	if s.Status != kms.SecretStatusPlain {
		return errWrongSecretStatus
	}
	if s.Payload == "" {
		return errInvalidSecret
	}
	secretKey, err := localsecrets.NewRandomKey()
	if err != nil {
		return err
	}
	key, err := s.deriveKey(secretKey[:], false)
	if err != nil {
		return err
	}
	keeper := localsecrets.NewKeeper(key)
	defer keeper.Close()

	ciphertext, err := keeper.Encrypt(context.Background(), []byte(s.Payload))
	if err != nil {
		return err
	}
	s.Key = hex.EncodeToString(secretKey[:])
	s.Payload = base64.StdEncoding.EncodeToString(ciphertext)
	s.Status = kms.SecretStatusSecretBox
	s.Mode = s.getEncryptionMode()
	return nil
}

func (s *LocalSecret) Decrypt() error {
	if s.Status != kms.SecretStatusSecretBox {
		return errWrongSecretStatus
	}
	encrypted, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return err
	}
	secretKey, err := hex.DecodeString(s.Key)
	if err != nil {
		return err
	}
	key, err := s.deriveKey(secretKey[:], true)
	if err != nil {
		return err
	}
	keeper := localsecrets.NewKeeper(key)
	defer keeper.Close()

	plaintext, err := keeper.Decrypt(context.Background(), encrypted)
	if err != nil {
		return err
	}
	s.Status = kms.SecretStatusPlain
	s.Payload = string(plaintext)
	s.Key = ""
	s.AdditionalData = ""
	s.Mode = 0
	return nil
}

func (s *LocalSecret) deriveKey(key []byte, isForDecryption bool) ([32]byte, error) {
	var masterKey []byte
	if s.MasterKey == "" || (isForDecryption && s.Mode == 0) {
		var combined []byte
		combined = append(combined, key...)
		if s.AdditionalData != "" {
			combined = append(combined, []byte(s.AdditionalData)...)
		}
		combined = append(combined, key...)
		hash := sha256.Sum256(combined)
		masterKey = hash[:]
	} else {
		masterKey = []byte(s.MasterKey)
	}
	var derivedKey [32]byte
	var info []byte
	if s.AdditionalData != "" {
		info = []byte(s.AdditionalData)
	}
	kdf := hkdf.New(sha256.New, masterKey, key, info)
	if _, err := io.ReadFull(kdf, derivedKey[:]); err != nil {
		return derivedKey, err
	}
	return derivedKey, nil
}

func (s *LocalSecret) getEncryptionMode() int {
	if s.MasterKey == "" {
		return 0
	}
	return 1
}
