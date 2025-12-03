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
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/containerd/go-dmverity/pkg/utils"
	verity "github.com/containerd/go-dmverity/pkg/verity"
)

func runFormat(p *verity.Params, dataPath, hashPath string) error {
	if !p.NoSuperblock && p.HashAreaOffset == 0 {
		p.HashAreaOffset = utils.AlignUp(uint64(verity.SuperblockSize), uint64(p.HashBlockSize))
	}

	if _, err := os.Stat(hashPath); errors.Is(err, os.ErrNotExist) {
		hashFile, createErr := os.OpenFile(hashPath, os.O_CREATE|os.O_RDWR, 0o600)
		if createErr != nil {
			return fmt.Errorf("create hash file %s: %w", hashPath, createErr)
		}
		hashFile.Close()
	} else if err != nil {
		return fmt.Errorf("stat hash path %s: %w", hashPath, err)
	}

	rootHash, err := verity.Create(p, dataPath, hashPath)
	if err != nil {
		return err
	}
	hashSize := utils.SelectHashSize(p.HashName)
	if hashSize <= 0 {
		return fmt.Errorf("unsupported hash algorithm: %s", p.HashName)
	}
	hashPerBlockBits := utils.GetBitsDown(p.HashBlockSize / uint32(hashSize))
	if hashPerBlockBits == 0 {
		return fmt.Errorf("hash block size %d is too small for hash size %d", p.HashBlockSize, hashSize)
	}
	hashesPerBlock := uint32(1 << hashPerBlockBits)

	var totalHashBlocks uint64
	remaining := p.DataBlocks
	for remaining > 1 {
		numBlocks := (remaining + uint64(hashesPerBlock) - 1) / uint64(hashesPerBlock)
		totalHashBlocks += numBlocks
		remaining = numBlocks
	}

	hashDeviceSize := totalHashBlocks * uint64(p.HashBlockSize)
	if !p.NoSuperblock {
		hashDeviceSize += utils.AlignUp(uint64(verity.SuperblockSize), uint64(p.HashBlockSize))
	}

	var uuidStr string
	if p.UUID != ([16]byte{}) {
		uuidFromBytes, _ := uuid.FromBytes(p.UUID[:])
		uuidStr = uuidFromBytes.String()
	}

	fmt.Printf("VERITY header information for %s\n", hashPath)
	fmt.Printf("UUID:                   %s\n", uuidStr)
	fmt.Printf("Format:                 %d\n", p.HashType)
	fmt.Printf("Data blocks:            %d\n", p.DataBlocks)
	fmt.Printf("Data block size:        %d\n", p.DataBlockSize)
	fmt.Printf("Hash blocks:            %d\n", totalHashBlocks)
	fmt.Printf("Hash block size:        %d\n", p.HashBlockSize)
	fmt.Printf("Hash algorithm:         %s\n", strings.ToLower(p.HashName))
	saltStr := "-"
	if len(p.Salt) > 0 {
		saltStr = hex.EncodeToString(p.Salt)
	}
	fmt.Printf("Salt:                   %s\n", saltStr)
	fmt.Printf("Root hash:              %s\n", hex.EncodeToString(rootHash))
	fmt.Printf("Hash device size:       %d [bytes]\n", hashDeviceSize)
	return nil
}

func parseFormatArgs(args []string) (*verity.Params, string, string, error) {
	fs := flag.NewFlagSet("format", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	flags := defaultFlags(fs)

	*flags.HashName = "sha256"
	*flags.DataBlockSize = 4096
	*flags.HashBlockSize = 4096

	if err := fs.Parse(args); err != nil {
		return nil, "", "", err
	}

	rest := fs.Args()
	if len(rest) != 2 {
		return nil, "", "", errors.New("require <data_path> and <hash_path>")
	}
	dataPath := rest[0]
	hashPath := rest[1]

	p := verity.DefaultParams()

	applyFlags(&p, flags)

	if p.HashName == "" {
		p.HashName = "sha256"
	}
	if *flags.DataBlockSize == 0 {
		*flags.DataBlockSize = 4096
	}
	if *flags.HashBlockSize == 0 {
		*flags.HashBlockSize = 4096
	}

	if err := validateAndApplyBlockSizes(&p, flags); err != nil {
		return nil, "", "", err
	}

	if err := utils.ValidateHashOffset(p.HashAreaOffset, p.HashBlockSize, p.NoSuperblock); err != nil {
		return nil, "", "", err
	}

	salt, saltSize, err := utils.ApplySalt(*flags.SaltHex, int(verity.MaxSaltSize))
	if err != nil {
		return nil, "", "", err
	}
	p.Salt = salt
	p.SaltSize = saltSize

	uuid, err := utils.ApplyUUID(*flags.UUIDStr, true, p.NoSuperblock, func() (string, error) {
		return uuid.New().String(), nil
	})
	if err != nil {
		return nil, "", "", err
	}
	p.UUID = uuid

	dataBlocks, err := utils.CalculateDataBlocks(dataPath, *flags.DataBlocks, p.DataBlockSize)
	if err != nil {
		return nil, "", "", err
	}
	p.DataBlocks = dataBlocks

	if err := utils.ValidateDataHashOverlap(p.DataBlocks, p.DataBlockSize, p.HashAreaOffset, dataPath, hashPath); err != nil {
		return nil, "", "", err
	}

	return &p, dataPath, hashPath, nil
}
