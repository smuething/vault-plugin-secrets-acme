# Vault ACME
[![Run tests](https://github.com/Boostport/vault-acme/actions/workflows/test.yml/badge.svg)](https://github.com/Boostport/vault-acme/actions/workflows/test.yml)

Vault ACME is a [Vault](https://www.vaultproject.io/) secret engine that allow
users and application to retrieve TLS certificates validated by an [ACME provider](https://tools.ietf.org/html/rfc8555)
like [Let's Encrypt](https://letsencrypt.org/) without having to give each
applications permission to modify DNS and using Vault's audit and policy systems.

Discussion: https://github.com/hashicorp/vault/issues/4950

## Download Vault ACME
Binary releases can be downloaded at https://github.com/Boostport/vault-acme/releases.

## Verify Binaries
The checksum for the binaries are signed with cosign. To verify the binaries, download the following files (where
`${VERSION}` is the version of the release):
- `vault-acme_${VERSION}_checksums.txt`
- `vault-acme_${VERSION}_checksums.txt.pem`
- `vault-acme_${VERSION}_checksums.txt.sig`

Then download the release binaries you need. Here, we just download the linux amd64 binary:
-  `vault-acme_${VERSION}_linux_amd64`

Then run the following commands to verify the checksums and signature:
```sh
# Verify checksum signature
$ cosign verify-blob --signature vault-acme_${VERSION}_checksums.txt.sig --certificate vault-acme_${VERSION}_checksums.txt.pem vault-acme_${VERSION}_checksums.txt --certificate-identity "https://github.com/Boostport/vault-acme/.github/workflows/release.yml@refs/tags/v${VERSION}" --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# Verify checksum with binaries
$ sha256sum -c vault-acme_${VERSION}_checksums.txt
```

## Documentation
The documentation is available at [`website/source/docs/secrets/acme/index.html.md`](website/source/docs/secrets/acme/index.html.md).

## How to Use
Using this plugin in Docker requires to manually set the `mlock` file capability
to both Vault and the acme plugin:

```sh
$ sudo setcap cap_ipc_lock=+ep $(readlink -f $(which vault))
$ sudo setcap cap_ipc_lock=+ep /vault/plugins/acme-plugin
```

After setting [`plugin_directory`](https://www.vaultproject.io/docs/configuration/#plugin_directory)
and setting the correct shasum in Vault (`vault write sys/plugins/catalog/secret/acme sha_256=$(sha256sum acme-plugin) command=acme-plugin`)
you can mount the plugin like any other: `vault secrets enable -path acme -plugin-name acme plugin`.


## Tests
The unit tests will use the `pebble` ACME test server and `pebble-challtestsrv`.
They can be downloaded at https://github.com/letsencrypt/pebble and must be
present in `$PATH`.

The unit tests can be run with:

```bash
$ make test
```

The acceptance tests needs Vault in addition to `pebble` and `pebble-challtestsrv`.

When `vault` is present in `$PATH` the acceptance tests can be run with:

```bash
$ make testacc
```
