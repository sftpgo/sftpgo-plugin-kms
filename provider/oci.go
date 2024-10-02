// Copyright (C) 2024 Nicola Murino
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

package provider

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

type ociDriver struct {
	keyID       string
	client      *keymanagement.KmsCryptoClient
	retryPolicy *common.RetryPolicy
}

func NewOCIDriver(URL string) (*ociDriver, error) {
	u, err := url.Parse(URL)
	if err != nil {
		return nil, err
	}

	var cp common.ConfigurationProvider
	if u.Query().Get("auth_type_api_key") == "1" {
		cp = common.DefaultConfigProvider()
	} else {
		cp, err = auth.InstancePrincipalConfigurationProvider()
		if err != nil {
			return nil, fmt.Errorf("unable to get instance principal configuration provider: %w", err)
		}
	}

	client, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(
		cp,
		os.Getenv("SFTPGO_PLUGIN_KMS_OCI_ENDPOINT"),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create crypto client: %w", err)
	}
	retryPolicy := common.NewRetryPolicyWithOptions(
		common.WithMaximumNumberAttempts(3),
		common.WithShouldRetryOperation(common.DefaultShouldRetryOperation),
		common.WithFixedBackoff(2*time.Second),
	)

	return &ociDriver{
		client:      &client,
		keyID:       u.Host,
		retryPolicy: &retryPolicy,
	}, nil
}

func (d *ociDriver) Encrypt(ctx context.Context, plaintext []byte) (ciphertext []byte, err error) {
	resp, err := d.client.Encrypt(ctx, keymanagement.EncryptRequest{
		EncryptDataDetails: keymanagement.EncryptDataDetails{
			KeyId:     common.String(d.keyID),
			Plaintext: common.String(string(plaintext)),
		},
		RequestMetadata: common.RequestMetadata{
			RetryPolicy: d.retryPolicy,
		},
	})
	if err != nil {
		return nil, err
	}
	return []byte(*resp.Ciphertext), nil
}

func (d *ociDriver) Decrypt(ctx context.Context, ciphertext []byte) (plaintext []byte, err error) {
	resp, err := d.client.Decrypt(ctx, keymanagement.DecryptRequest{
		DecryptDataDetails: keymanagement.DecryptDataDetails{
			KeyId:      common.String(d.keyID),
			Ciphertext: common.String(string(ciphertext)),
		},
		RequestMetadata: common.RequestMetadata{
			RetryPolicy: d.retryPolicy,
		},
	})
	if err != nil {
		return nil, err
	}
	return []byte(*resp.Plaintext), nil
}

func (d *ociDriver) Close() error {
	d.client = nil
	d.retryPolicy = nil
	return nil
}
