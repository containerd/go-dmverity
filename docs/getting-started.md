# Getting Started

A guide for using `go-dmverity` as a Go library and CLI tool.

## Installation

### As a Library

```bash
go get github.com/containerd/go-dmverity
```

### CLI Tool

```bash
# Install using go install
go install github.com/containerd/go-dmverity/cmd/go-dmverity@latest

# Or build from source
git clone https://github.com/containerd/go-dmverity.git
cd go-dmverity
make
```

## Library Usage

### Quick Start

```go
package main

import (
    "fmt"
    "log"
    "github.com/containerd/go-dmverity/pkg/utils"
    "github.com/containerd/go-dmverity/pkg/verity"
)

func main() {
    // Create hash tree
    params := verity.DefaultParams()
    params.HashName = "sha256"
    
    size, err := utils.GetBlockOrFileSize("data.img")
    if err != nil {
        log.Fatal(err)
    }
    params.DataBlocks = uint64(size / int64(params.DataBlockSize))
    
    rootHash, err := verity.Create(&params, "data.img", "hash.img")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Root hash: %x\n", rootHash)
    
    // Verify data
    err = verity.Verify(&params, "data.img", "hash.img", rootHash)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Verification successful!")
}
```

## CLI Usage

The CLI tool provides a convenient interface for common operations.

### Commands

| Command | Description |
|---------|-------------|
| `format` | Create dm-verity hash tree |
| `verify` | Validate data against root hash |
| `open` | Activate dm-verity device (Linux only) |
| `close` | Deactivate dm-verity device (Linux only) |
| `status` | Display device information (Linux only) |
| `dump` | Display superblock information |

### Quick Examples

```bash
# Create test data
dd if=/dev/urandom of=data.img bs=4096 count=256

# Format with dm-verity
go-dmverity format --hash sha256 data.img hash.img
# Output: Root hash: a1b2c3d4e5f6...

# Verify the data
go-dmverity verify data.img hash.img <root-hash>

# Activate device (Linux only, requires root)
sudo go-dmverity open data.img my-verity hash.img <root-hash>

# Check status
sudo go-dmverity status my-verity

# Close device
sudo go-dmverity close my-verity

# Display superblock info
go-dmverity dump hash.img
```

### Common Options

| Option | Description | Default |
|--------|-------------|---------|
| `--hash <algorithm>` | Hash algorithm (sha1, sha256, sha512) | sha256 |
| `--data-block-size <bytes>` | Data block size | 4096 |
| `--hash-block-size <bytes>` | Hash block size | 4096 |
| `--no-superblock` | Legacy format without superblock | false |
| `--salt <hex\|->` | Custom salt or '-' for none | auto-generated |
| `--uuid <uuid>` | Custom UUID for superblock | auto-generated |
