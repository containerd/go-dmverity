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
	"strings"

	"github.com/containerd/go-dmverity/pkg/dm"
	"github.com/containerd/go-dmverity/pkg/utils"
	verity "github.com/containerd/go-dmverity/pkg/verity"
)

func parseOpenArgs(args []string) (*verity.Params, string, string, string, []byte, []string, string, error) {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	flags := defaultFlags(fs)

	if err := fs.Parse(args); err != nil {
		return nil, "", "", "", nil, nil, "", err
	}

	rest := fs.Args()
	if len(rest) < 4 {
		return nil, "", "", "", nil, nil, "", errors.New("require <data_device> <name> <hash_device> <root_hash>")
	}
	dataDev := rest[0]
	name := rest[1]
	hashDev := rest[2]
	rootHex := rest[3]

	if strings.TrimSpace(name) == "" {
		return nil, "", "", "", nil, nil, "", fmt.Errorf("device name is required")
	}
	if strings.Contains(name, "/") {
		return nil, "", "", "", nil, nil, "", fmt.Errorf("device name must not contain '/' characters")
	}
	if len(name) >= dm.DMNameLen {
		return nil, "", "", "", nil, nil, "", fmt.Errorf("device name too long (max %d characters)", dm.DMNameLen-1)
	}

	p := verity.DefaultParams()

	applyFlags(&p, flags)

	if !*flags.NoSuper {
		p.HashName = ""
		p.DataBlockSize = 0
		p.HashBlockSize = 0
	}

	if err := validateAndApplyBlockSizes(&p, flags); err != nil {
		return nil, "", "", "", nil, nil, "", err
	}

	if err := utils.ValidateHashOffset(p.HashAreaOffset, p.HashBlockSize, p.NoSuperblock); err != nil {
		return nil, "", "", "", nil, nil, "", err
	}

	salt, saltSize, err := utils.ApplySalt(*flags.SaltHex, int(verity.MaxSaltSize))
	if err != nil {
		return nil, "", "", "", nil, nil, "", err
	}
	p.Salt = salt
	p.SaltSize = saltSize

	if *flags.NoSuper {
		dataBlocks, err := utils.CalculateDataBlocks(dataDev, *flags.DataBlocks, p.DataBlockSize)
		if err != nil {
			return nil, "", "", "", nil, nil, "", err
		}
		p.DataBlocks = dataBlocks
	}

	rootBytes, err := utils.ParseRootHash(rootHex)
	if err != nil {
		return nil, "", "", "", nil, nil, "", err
	}

	var dmFlags []string
	signatureFile := *flags.RootHashSig
	return &p, dataDev, name, hashDev, rootBytes, dmFlags, signatureFile, nil
}

func runOpen(p *verity.Params, dataDev, name, hashDev string, rootDigest []byte, flags []string, signatureFile string) error {
	if p == nil {
		return fmt.Errorf("verity params is nil")
	}
	if name == "" {
		return fmt.Errorf("device name is required")
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf("device name must not contain '/' characters")
	}

	dataLoop, cleanup, err := utils.SetupLoopDevice(dataDev)
	if err != nil {
		return fmt.Errorf("setup data loop device: %w", err)
	}
	defer func() {
		if dataLoop != dataDev {
			cleanup()
		}
	}()

	hashLoop, cleanupHash, err := utils.SetupLoopDevice(hashDev)
	if err != nil {
		return fmt.Errorf("setup hash loop device: %w", err)
	}
	defer func() {
		if hashLoop != hashDev {
			cleanupHash()
		}
	}()

	devPath, err := verity.Open(p, name, dataLoop, hashLoop, rootDigest, signatureFile, flags)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", devPath)
	return nil
}
