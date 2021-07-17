# SFTPGo KMS plugin

![Build](https://github.com/sftpgo/sftpgo-plugin-kms/workflows/Build/badge.svg?branch=main&event=push)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

This plugin adds support for additional KMS secret providers to [SFTPGo](https://github.com/drakkan/sftpgo/).

## Supported Services

This plugin use [Go CDK](https://gocloud.dev/howto/secrets/) to access several key management services in a portable way.

The supported services can be configured within the `plugins` section of the SFTPGo configuration file. This is an example configuration.

```json
...
"kms": {
    "secrets": {
      "url": "hashivault://my-key",
      "master_key_path": ""
    }
},
"plugins": [
    {
      "type": "kms",
      "kms_options": {
        "scheme": "hashivault",
        "encrypted_status": "VaultTransit"
      },
      "cmd": "<path to sftpgo-plugin-kms>",
      "args": [],
      "sha256sum": "",
      "auto_mtls": true
    }
]
...
```

In the above example we enabled the [transit secrets engine](https://www.vaultproject.io/docs/secrets/transit/index.html) in [Vault](https://www.vaultproject.io/).

### Google Cloud Key Management Service

To use keys from Google Cloud Platform’s [Key Management Service](https://cloud.google.com/kms/) (GCP KMS) you have to use `gcpkms` as URL scheme like this.

```shell
gcpkms://projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]
```

SFTPGo will use Application Default Credentials. See [here](https://cloud.google.com/docs/authentication/production) for alternatives such as environment variables.

The URL host+path are used as the key resource ID; see [here](https://cloud.google.com/kms/docs/object-hierarchy#key) for more details.

If a master key is provided we first encrypt the plaintext data using the SFTPGo local provider and then we encrypt the resulting payload using the Cloud provider and store this ciphertext.

In the configuration section `kms_options` set:

- `scheme` to `gcpkms`
- `encrypted_status` to `GCP`

### AWS Key Management Service

To use customer master keys from Amazon Web Service’s [Key Management Service](https://aws.amazon.com/kms/) (AWS KMS) you have to use `awskms` as URL scheme. You can use the key’s ID, alias, or Amazon Resource Name (ARN) to identify the key. You should specify the region query parameter to ensure your application connects to the correct region.

Here are some examples:

- By ID: `awskms://1234abcd-12ab-34cd-56ef-1234567890ab?region=us-east-1`
- By alias: `awskms://alias/ExampleAlias?region=us-east-1`
- By ARN: `arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34bc-56ef-1234567890ab?region=us-east-1`

SFTPGo will use the default AWS session. See [AWS Session](https://docs.aws.amazon.com/sdk-for-go/api/aws/session/) to learn about authentication alternatives such as environment variables.

If a master key is provided we first encrypt the plaintext data using the SFTPGo local provider and then we encrypt the resulting payload using the Cloud provider and store this ciphertext.

In the configuration section `kms_options` set:

- `scheme` to `awskms`
- `encrypted_status` to `AWS`

### Azure KeyVault

To use keys from [Azure KeyVault](https://azure.microsoft.com/en-us/services/key-vault/) you have to use `azurekeyvault` as URL scheme. Here is an example URL.

```shell
azurekeyvault://mykeyvaultname.vault.azure.net/keys/mykeyname
```

The "azurekeyvault" URL scheme is replaced with "https" to construct an Azure Key Vault keyID, as described [here](https://docs.microsoft.com/en-us/azure/key-vault/about-keys-secrets-and-certificates). You can add an optional "/{key-version}" to the path to use a specific version of the key; it defaults to the latest version.

SFTPGo will use the default credentials from the [environment](https://docs.microsoft.com/en-us/go/azure/azure-sdk-go-authorization#use-environment-based-authentication).

If a master key is provided we first encrypt the plaintext data using the SFTPGo local provider and then we encrypt the resulting payload using the Cloud provider and store this ciphertext.

In the configuration section `kms_options` set:

- `scheme` to `azurekeyvault`
- `encrypted_status` to `AzureKeyVault`

### HashiCorp Vault

To use the [transit secrets engine](https://www.vaultproject.io/docs/secrets/transit/index.html) in [Vault](https://www.vaultproject.io/) you have to use `hashivault` as URL scheme like this: `hashivault://my-key`.

The Vault server endpoint and authentication token are specified using the environment variables `VAULT_SERVER_URL` and `VAULT_SERVER_TOKEN`, respectively.

If a master key is provided we first encrypt the plaintext data using the SFTPGo local provider and then we encrypt the resulting payload using Vault and store this ciphertext.

In the configuration section `kms_options` set:

- `scheme` to `hashivault`
- `encrypted_status` to `VaultTransit`
