# encrypt-remote-hook

A rust-based initcpio hook to configure full-disk encryption by reading a secret key from a remote endpoint.

This hook supports a threat-model based on device theft, but not necessarily based on malicious tampering. Use this hook to naively provision XOR-split key material in multiple locations and decrypt the disk based on that.

## Usage

Make sure to add a network hook!

Configure the hook by placing a configuration file in `/etc/crypttab.remote.toml`:

```toml
[device]
block = "PARTUUID=9f383516-9660-44a1-911f-f8f07d0b8065"
name = "root"

[[key]]
type = "https"
url = "https://example.com/path/to/key"

[[key]]
type = "rootfs"
path = "/cryptokey"
```

This configuration will prompt `encrypt-remote-hook` to fetch two key parts and XOR them together, then `cryptsetup` the specified block as `/dev/mapper/root`.

## Roadmap

* TPM support
* Yubikey support
* Local, non-rootfs support
* Multiple fallbacks for the same key part
