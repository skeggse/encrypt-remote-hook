# encrypt-remote-hook

A rust-based initcpio hook to configure full-disk encryption by reading a secret key from a remote endpoint.

This hook supports a threat-model based on device theft, but not necessarily based on malicious tampering. Use this hook to naively provision XOR-split key material in multiple locations and decrypt the disk based on that.

This hook does not consider or respect any kernel command line parameters, including `cryptdevice` and `cryptkey`. The hook should work under Arch Linux, and with some manual tweaking you might manage to get it to work on other distributions. Happy to chat about how to adapt this package for other uses!

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
* Extra network headers for pseudo-authentication
* Configurable timeouts to permit multi-factor https-based key vending
* (Authenticated) AWS S3
* Multiple fallbacks for the same key part (and for the entire key, for recovery)
* Support passphrase-based fallback

## Credits

Some of the package boilerplate adapted from [fuhry/initramfs-scencrypt](https://github.com/fuhry/initramfs-scencrypt).


## FAQ

### Why rust?

I wanted to use rust. It certainly wasn't a good use of my time, unless you include the things I learned! Beyond that, it seemed interesting to see how far a statically linked binary could go here, though it probably wants some pretty serious space optimization to be reasonable for this context.


## License

I've licensed this under the MIT license. Ymmv. Please take careful note of the no-warranty clause. I'm not a cryptographer and this is probably a bad idea.
