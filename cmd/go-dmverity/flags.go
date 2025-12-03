/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/containerd/go-dmverity/pkg/utils"
	verity "github.com/containerd/go-dmverity/pkg/verity"
)

type CommonFlags struct {
	HashName      *string
	DataBlockSize *uint
	HashBlockSize *uint
	SaltHex       *string
	DataBlocks    *uint64
	NoSuper       *bool
	HashOffset    *uint64
	UUIDStr       *string
	FormatType    *uint
	RootHashSig   *string
}

func defaultFlags(fs *flag.FlagSet) *CommonFlags {
	return &CommonFlags{
		HashName:      fs.String("hash", "", "hash algorithm"),
		DataBlockSize: fs.Uint("data-block-size", 0, "data block size in bytes"),
		HashBlockSize: fs.Uint("hash-block-size", 0, "hash block size in bytes"),
		SaltHex:       fs.String("salt", "", "salt as hex string or '-' for none"),
		DataBlocks:    fs.Uint64("data-blocks", 0, "number of data blocks (override file size)"),
		NoSuper:       fs.Bool("no-superblock", false, "omit/ignore verity superblock"),
		HashOffset:    fs.Uint64("hash-offset", 0, "hash area offset when no superblock"),
		UUIDStr:       fs.String("uuid", "", "UUID (RFC4122)"),
		FormatType:    fs.Uint("format", 1, "Format type (1 - normal, 0 - original Chrome OS)"),
		RootHashSig:   fs.String("root-hash-signature", "", "Path to root hash signature file"),
	}
}

func validateAndApplyBlockSizes(p *verity.Params, flags *CommonFlags) error {
	if *flags.NoSuper {
		if p.DataBlockSize == 0 {
			p.DataBlockSize = 4096
		}
		if p.HashBlockSize == 0 {
			p.HashBlockSize = 4096
		}
	}

	if *flags.DataBlockSize != 0 {
		if !utils.IsBlockSizeValid(uint32(*flags.DataBlockSize)) {
			return fmt.Errorf("invalid data block size: %d", *flags.DataBlockSize)
		}
		p.DataBlockSize = uint32(*flags.DataBlockSize)
	}

	if *flags.HashBlockSize != 0 {
		if !utils.IsBlockSizeValid(uint32(*flags.HashBlockSize)) {
			return fmt.Errorf("invalid hash block size: %d", *flags.HashBlockSize)
		}
		p.HashBlockSize = uint32(*flags.HashBlockSize)
	}

	return nil
}

func applyFlags(p *verity.Params, flags *CommonFlags) {
	p.HashType = uint32(*flags.FormatType)
	p.NoSuperblock = *flags.NoSuper
	p.HashAreaOffset = *flags.HashOffset

	if *flags.HashName != "" {
		p.HashName = strings.ToLower(*flags.HashName)
	}
}
