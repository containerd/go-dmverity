# go-dmverity

`go-dmverity` is a containerd sub-project that provides a complete dm-verity implementation in pure Go. It enables developers to integrate dm-verity functionality directly into their Go applications without requiring external dependencies or system tools.

### Features

- **Hash tree creation and verification** - Build and verify Merkle trees for data integrity
- **Multiple hash algorithms** - Support for SHA1, SHA256, SHA512
- **Flexible formats** - Superblock and legacy (Chrome OS) formats
- **Device activation** - Pure Go device-mapper interface for Linux
- **Signature verification** - Root hash signature support
- **Tools compatible** - Interoperable with standard `veritysetup` tools

## Quick Start

See the [Guide](docs/getting-started.md) for complete installation and usage instructions.

## Project Details

Go-dmverity is a containerd sub-project, licensed under the [Apache 2.0 license](./LICENSE).

As a containerd sub-project, you will find the:
 * [Project governance](https://github.com/containerd/project/blob/main/GOVERNANCE.md),
 * [Maintainers](https://github.com/containerd/project/blob/main/MAINTAINERS),
 * and [Contributing guidelines](https://github.com/containerd/project/blob/main/CONTRIBUTING.md)

information in our [`containerd/project`](https://github.com/containerd/project) repository.

## References

- [dm-verity kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html)
- [veritysetup man page](https://man7.org/linux/man-pages/man8/veritysetup.8.html)