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

package main

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"gocloud.dev/secrets"
	_ "gocloud.dev/secrets/awskms"
	_ "gocloud.dev/secrets/azurekeyvault"
	_ "gocloud.dev/secrets/gcpkms"
	_ "gocloud.dev/secrets/hashivault"

	"github.com/sftpgo/sdk/kms"
	kmsplugin "github.com/sftpgo/sdk/plugin/kms"

	"github.com/sftpgo/sftpgo-plugin-kms/provider"
	"github.com/sftpgo/sftpgo-plugin-kms/secret"
)

const version = "1.0.15"

var (
	commitHash = ""
	date       = ""
)

var appLogger = hclog.New(&hclog.LoggerOptions{
	DisableTime: true,
	Level:       hclog.Debug,
})

type GoCloudKMS struct {
	timeout time.Duration
}

func (k *GoCloudKMS) Encrypt(payload, additionalData, URL, masterKey string) (string, string, int32, error) {
	key := ""
	mode := 0
	if masterKey != "" {
		baseSecret := kms.BaseSecret{
			Status:         kms.SecretStatusPlain,
			Payload:        payload,
			AdditionalData: additionalData,
		}
		localSecret := secret.LocalSecret{
			BaseSecret: baseSecret,
			MasterKey:  masterKey,
		}
		err := localSecret.Encrypt()
		if err != nil {
			appLogger.Warn("unable to encrypt local secret", "error", err)
			return "", "", 0, err
		}
		payload = localSecret.GetPayload()
		key = localSecret.GetKey()
		mode = localSecret.GetMode()
	}

	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(k.timeout))
	defer cancelFn()

	keeper, err := getKeeper(ctx, URL)
	if err != nil {
		appLogger.Warn("unable to open keeper to encrypt", "URL", URL, "error", err)
		return "", "", 0, err
	}
	defer keeper.Close()

	ciphertext, err := keeper.Encrypt(ctx, []byte(payload))
	if err != nil {
		appLogger.Warn("unable to encrypt", "URL", URL, "error", err)
		return "", "", 0, err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), key, int32(mode), nil
}

func (k *GoCloudKMS) Decrypt(payload, key, additionalData string, mode int, URL, masterKey string) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		appLogger.Warn("unable to decode as base64 payload to decrypt", "error", err)
		return "", err
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(k.timeout))
	defer cancelFn()

	keeper, err := getKeeper(ctx, URL)
	if err != nil {
		appLogger.Warn("unable to open keeper to decrypt", "URL", URL, "error", err)
		return "", err
	}
	defer keeper.Close()

	plaintext, err := keeper.Decrypt(ctx, encrypted)
	if err != nil {
		appLogger.Warn("unable to decrypt", "URL", URL, "error", err)
		return "", err
	}
	decrypted := string(plaintext)
	if key != "" {
		baseSecret := kms.BaseSecret{
			Status:         kms.SecretStatusSecretBox,
			Payload:        decrypted,
			Key:            key,
			AdditionalData: additionalData,
			Mode:           mode,
		}
		localSecret := secret.LocalSecret{
			BaseSecret: baseSecret,
			MasterKey:  masterKey,
		}
		err = localSecret.Decrypt()
		if err != nil {
			appLogger.Warn("unable to decrypt local secret", "error", err)
			return "", err
		}
		decrypted = localSecret.GetPayload()
	}
	return decrypted, nil
}

func getKeeper(ctx context.Context, URL string) (provider.Driver, error) {
	if strings.HasPrefix(URL, "ocikeyvault://") {
		return provider.NewOCIDriver(URL)
	}
	return secrets.OpenKeeper(ctx, URL)
}

func getVersionString() string {
	var sb strings.Builder
	sb.WriteString(version)
	if commitHash != "" {
		sb.WriteString("-")
		sb.WriteString(commitHash)
	}
	if date != "" {
		sb.WriteString("-")
		sb.WriteString(date)
	}
	return sb.String()
}

func main() {
	appLogger.Info("starting sftpgo-plugin-kms", "version", getVersionString())
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: kmsplugin.Handshake,
		Plugins: map[string]plugin.Plugin{
			kmsplugin.PluginName: &kmsplugin.Plugin{Impl: &GoCloudKMS{
				timeout: 15 * time.Second,
			}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
