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
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/google/uuid"

	"github.com/containerd/go-dmverity/pkg/utils"
	verity "github.com/containerd/go-dmverity/pkg/verity"
)

func parseVerifyArgs(args []string) (*verity.Params, string, string, []byte, error) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	flags := defaultFlags(fs)

	if err := fs.Parse(args); err != nil {
		return nil, "", "", nil, err
	}

	rest := fs.Args()
	if len(rest) != 3 {
		return nil, "", "", nil, errors.New("require <data_path> <hash_path> <root_hex>")
	}
	dataPath := rest[0]
	hashPath := rest[1]

	p := verity.DefaultParams()

	applyFlags(&p, flags)

	if !*flags.NoSuper {
		p.HashName = ""
		p.DataBlockSize = 0
		p.HashBlockSize = 0
	}

	if err := validateAndApplyBlockSizes(&p, flags); err != nil {
		return nil, "", "", nil, err
	}

	if err := utils.ValidateHashOffset(p.HashAreaOffset, p.HashBlockSize, p.NoSuperblock); err != nil {
		return nil, "", "", nil, err
	}

	salt, saltSize, err := utils.ApplySalt(*flags.SaltHex, int(verity.MaxSaltSize))
	if err != nil {
		return nil, "", "", nil, err
	}
	p.Salt = salt
	p.SaltSize = saltSize

	if p.NoSuperblock {
		dataBlocks, err := utils.CalculateDataBlocks(dataPath, *flags.DataBlocks, p.DataBlockSize)
		if err != nil {
			return nil, "", "", nil, err
		}
		p.DataBlocks = dataBlocks
	}

	if p.NoSuperblock {
		uuid, err := utils.ApplyUUID(*flags.UUIDStr, false, p.NoSuperblock, func() (string, error) {
			return uuid.New().String(), nil
		})
		if err != nil {
			return nil, "", "", nil, err
		}
		p.UUID = uuid
	}

	rootBytes, err := utils.ParseRootHash(rest[2])
	if err != nil {
		return nil, "", "", nil, err
	}

	return &p, dataPath, hashPath, rootBytes, nil
}

func runVerify(p *verity.Params, dataPath, hashPath string, rootDigest []byte) error {
	if p.HashName != "" {
		if err := utils.ValidateRootHashSize(rootDigest, p.HashName); err != nil {
			return err
		}
	}

	if err := verity.Verify(p, dataPath, hashPath, rootDigest); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	fmt.Printf("Verification succeeded\n")
	return nil
}
