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

package verity

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"regexp"
	"testing"
)

type merkleTestConfig struct {
	name          string
	dataBlockSize uint32
	hashBlockSize uint32
	numBlocks     uint64
	hashType      uint32
	hashAlgo      string
	useSalt       bool
}

var commonMerkleTests = []merkleTestConfig{
	{"basic test - no salt", 4096, 4096, 16, 1, "sha256", false},
	{"with salt", 4096, 4096, 32, 1, "sha256", true},
	{"sha512", 4096, 4096, 16, 1, "sha512", false},
}

func createTestDataFile(t *testing.T, blockSize uint32, numBlocks uint64) (string, []byte) {
	t.Helper()

	dataFile, err := os.CreateTemp("", "verity-test-data-*")
	if err != nil {
		t.Fatalf("failed to create temp data file: %v", err)
	}

	totalSize := uint64(blockSize) * numBlocks
	data := make([]byte, totalSize)
	if _, err := rand.Read(data); err != nil {
		dataFile.Close()
		os.Remove(dataFile.Name())
		t.Fatalf("failed to generate random data: %v", err)
	}

	if _, err := dataFile.Write(data); err != nil {
		dataFile.Close()
		os.Remove(dataFile.Name())
		t.Fatalf("failed to write test data: %v", err)
	}

	if err := dataFile.Sync(); err != nil {
		dataFile.Close()
		os.Remove(dataFile.Name())
		t.Fatalf("failed to sync data file: %v", err)
	}

	dataFile.Close()
	return dataFile.Name(), data
}

func createTestHashFile(t *testing.T, size int64) string {
	t.Helper()

	hashFile, err := os.CreateTemp("", "verity-test-hash-*")
	if err != nil {
		t.Fatalf("failed to create temp hash file: %v", err)
	}

	if size > 0 {
		if err := hashFile.Truncate(size); err != nil {
			hashFile.Close()
			os.Remove(hashFile.Name())
			t.Fatalf("failed to truncate hash file: %v", err)
		}
	}

	hashFile.Close()
	return hashFile.Name()
}

func extractRootHash(t *testing.T, output string) string {
	t.Helper()
	re := regexp.MustCompile(`(?i)Root hash:\s*([0-9a-f]+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) < 2 {
		t.Fatalf("failed to extract root hash from output: %s", output)
	}
	return matches[1]
}

func createParamsFromConfig(tc merkleTestConfig, salt []byte) *Params {
	return &Params{
		HashName:       tc.hashAlgo,
		DataBlockSize:  tc.dataBlockSize,
		HashBlockSize:  tc.hashBlockSize,
		DataBlocks:     tc.numBlocks,
		HashType:       tc.hashType,
		Salt:           salt,
		SaltSize:       uint16(len(salt)),
		HashAreaOffset: 0,
	}
}

func createCryptHash(params *Params, dataPath, hashPath string, rootHash []byte) *CryptHash {
	return NewCryptHash(
		params.HashName,
		params.DataBlockSize, params.HashBlockSize,
		params.DataBlocks,
		params.HashType,
		params.Salt,
		params.HashAreaOffset,
		dataPath, hashPath,
		rootHash,
	)
}

func prepareSaltAndArgs(useSalt bool, saltPrefix string) ([]byte, []string) {
	if !useSalt {
		return nil, []string{"--salt", "-"}
	}
	salt := []byte(saltPrefix)
	saltHex := hex.EncodeToString(salt)
	return salt, []string{"--salt", saltHex}
}

func runVeritysetup(t *testing.T, dataPath, hashPath, hashAlgo string, saltArgs []string) []byte {
	t.Helper()
	args := []string{
		"format", dataPath, hashPath,
		"--hash", hashAlgo,
		"--data-block-size", "4096",
		"--hash-block-size", "4096",
	}
	args = append(args, saltArgs...)

	cmd := exec.Command("veritysetup", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veritysetup format failed: %v\nOutput: %s", err, string(output))
	}

	rootHashHex := extractRootHash(t, string(output))
	rootHashBytes, err := hex.DecodeString(rootHashHex)
	if err != nil {
		t.Fatalf("failed to decode cryptsetup root hash: %v", err)
	}
	return rootHashBytes
}

func TestHashFileContentComparison(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping hash file comparison test")
	}

	for _, tt := range commonMerkleTests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, tt.dataBlockSize, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPathGo := createTestHashFile(t, int64(tt.hashBlockSize*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathGo)

			hashPathC := createTestHashFile(t, int64(tt.hashBlockSize*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathC)

			salt, saltArgs := prepareSaltAndArgs(tt.useSalt, "comparison-test-salt")
			params := createParamsFromConfig(tt, salt)

			vhGo := createCryptHash(params, dataPath, hashPathGo, nil)
			if err := vhGo.CreateOrVerifyHashTree(false); err != nil {
				t.Fatalf("Go CreateOrVerifyHashTree failed: %v", err)
			}
			rootHashGo := vhGo.RootHash()

			rootHashCBytes := runVeritysetup(t, dataPath, hashPathC, tt.hashAlgo, saltArgs)

			if !bytes.Equal(rootHashGo, rootHashCBytes) {
				t.Errorf("Root hash mismatch:\nGo:         %x\ncryptsetup: %x",
					rootHashGo, rootHashCBytes)
			}

			hashContentCFull, err := os.ReadFile(hashPathC)
			if err != nil {
				t.Fatalf("failed to read cryptsetup hash file: %v", err)
			}

			superblockSize := int(tt.hashBlockSize)
			if len(hashContentCFull) > superblockSize {
				hashPathCStripped := createTestHashFile(t, int64(tt.hashBlockSize*uint32(tt.numBlocks)*2))
				defer os.Remove(hashPathCStripped)

				hashTreeOnly := hashContentCFull[superblockSize:]
				if err := os.WriteFile(hashPathCStripped, hashTreeOnly, 0644); err != nil {
					t.Fatalf("failed to write stripped hash file: %v", err)
				}

				vhVerifyStripped := createCryptHash(params, dataPath, hashPathCStripped, rootHashCBytes)
				if err := vhVerifyStripped.CreateOrVerifyHashTree(true); err != nil {
					t.Errorf("Go verifying stripped cryptsetup hash FAILED (%v)", err)
				}
			}

			vhVerifyGo := createCryptHash(params, dataPath, hashPathGo, rootHashGo)
			if err := vhVerifyGo.CreateOrVerifyHashTree(true); err != nil {
				t.Errorf("Go verifying own hash FAILED (%v)", err)
			}
		})
	}
}

func TestCrossCheckWithCryptsetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping cross-check test")
	}

	for _, tt := range commonMerkleTests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, tt.dataBlockSize, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPathGo := createTestHashFile(t, int64(tt.hashBlockSize*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathGo)

			hashPathC := createTestHashFile(t, int64(tt.hashBlockSize*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathC)

			salt, saltArgs := prepareSaltAndArgs(tt.useSalt, "cross-check-salt")
			params := createParamsFromConfig(tt, salt)

			vhGo := createCryptHash(params, dataPath, hashPathGo, nil)
			if err := vhGo.CreateOrVerifyHashTree(false); err != nil {
				t.Fatalf("Go CreateOrVerifyHashTree failed: %v", err)
			}
			rootHashGo := vhGo.RootHash()

			rootHashCBytes := runVeritysetup(t, dataPath, hashPathC, tt.hashAlgo, saltArgs)

			if !bytes.Equal(rootHashGo, rootHashCBytes) {
				t.Errorf("Root hash mismatch:\nGo:         %x\ncryptsetup: %x",
					rootHashGo, rootHashCBytes)
			}

			vhSelfVerify := createCryptHash(params, dataPath, hashPathGo, rootHashGo)
			if err := vhSelfVerify.CreateOrVerifyHashTree(true); err != nil {
				t.Errorf("Go failed to verify its own hash tree: %v", err)
			}
		})
	}
}

func TestManualHashTreeVerification(t *testing.T) {
	const (
		dataBlockSize = uint32(4096)
		hashBlockSize = uint32(4096)
		numBlocks     = uint64(4)
	)

	dataPath, err := os.CreateTemp("", "manual-verify-data-*")
	if err != nil {
		t.Fatalf("failed to create data file: %v", err)
	}
	defer os.Remove(dataPath.Name())

	for i := uint64(0); i < numBlocks; i++ {
		block := make([]byte, dataBlockSize)
		for j := range block {
			block[j] = byte(i)
		}
		if _, err := dataPath.Write(block); err != nil {
			t.Fatalf("failed to write data: %v", err)
		}
	}
	if err := dataPath.Sync(); err != nil {
		t.Fatalf("Failed to sync data file: %v", err)
	}
	dataPath.Close()

	hashPath := createTestHashFile(t, int64(hashBlockSize*uint32(numBlocks)))
	defer os.Remove(hashPath)

	salt := []byte("manual-test")
	params := &Params{
		HashName: "sha256", DataBlockSize: dataBlockSize, HashBlockSize: hashBlockSize,
		DataBlocks: numBlocks, HashType: 1, Salt: salt, SaltSize: uint16(len(salt)),
		HashAreaOffset: 0,
	}

	vh := createCryptHash(params, dataPath.Name(), hashPath, nil)
	if err := vh.CreateOrVerifyHashTree(false); err != nil {
		t.Fatalf("CreateOrVerifyHashTree failed: %v", err)
	}
	rootHash := vh.RootHash()

	dataFile, err := os.Open(dataPath.Name())
	if err != nil {
		t.Fatalf("failed to open data file: %v", err)
	}
	defer dataFile.Close()

	for i := uint64(0); i < numBlocks; i++ {
		block := make([]byte, dataBlockSize)
		if _, err := dataFile.Read(block); err != nil {
			t.Fatalf("failed to read block %d: %v", i, err)
		}

		if _, err := vh.verifyHashBlock(block, salt); err != nil {
			t.Fatalf("failed to calculate hash for block %d: %v", i, err)
		}
	}

	vhVerify := createCryptHash(params, dataPath.Name(), hashPath, rootHash)
	if err := vhVerify.CreateOrVerifyHashTree(true); err != nil {
		t.Errorf("verification failed: %v", err)
	}
}

func TestHashTreeStructure(t *testing.T) {
	const (
		dataBlockSize = uint32(4096)
		hashBlockSize = uint32(4096)
		numBlocks     = uint64(256)
	)

	dataPath, _ := createTestDataFile(t, dataBlockSize, numBlocks)
	defer os.Remove(dataPath)

	hashPath := createTestHashFile(t, int64(hashBlockSize*uint32(numBlocks)*2))
	defer os.Remove(hashPath)

	salt := []byte("structure-test")
	params := &Params{
		HashName: "sha256", DataBlockSize: dataBlockSize, HashBlockSize: hashBlockSize,
		DataBlocks: numBlocks, HashType: 1, Salt: salt, SaltSize: uint16(len(salt)),
		HashAreaOffset: 0,
	}

	vh := createCryptHash(params, dataPath, hashPath, nil)

	if _, err := vh.hashLevels(numBlocks); err != nil {
		t.Fatalf("hashLevels failed: %v", err)
	}

	if err := vh.CreateOrVerifyHashTree(false); err != nil {
		t.Fatalf("CreateOrVerifyHashTree failed: %v", err)
	}
	rootHash := vh.RootHash()

	vhVerify := createCryptHash(params, dataPath, hashPath, rootHash)
	if err := vhVerify.CreateOrVerifyHashTree(true); err != nil {
		t.Errorf("verification failed: %v", err)
	}
}

func TestCryptHashGetHashTreeSize(t *testing.T) {
	tests := []struct {
		name          string
		dataBlocks    uint64
		hashAlgo      string
		dataBlockSize uint32
		hashBlockSize uint32
	}{
		{"sha256 16 blocks 4K", 16, "sha256", 4096, 4096},
		{"sha256 128 blocks 4K", 128, "sha256", 4096, 4096},
		{"sha256 129 blocks 4K", 129, "sha256", 4096, 4096},
		{"sha256 1024 blocks 4K", 1024, "sha256", 4096, 4096},
		{"sha512 16 blocks 4K", 16, "sha512", 4096, 4096},
		{"sha512 64 blocks 4K", 64, "sha512", 4096, 4096},
		{"sha1 32 blocks 4K", 32, "sha1", 4096, 4096},
		{"sha256 10000 blocks 4K", 10000, "sha256", 4096, 4096},

		{"sha256 64 blocks 512B", 64, "sha256", 512, 512},
		{"sha256 256 blocks 512B", 256, "sha256", 512, 512},
		{"sha512 128 blocks 512B", 128, "sha512", 512, 512},
		{"sha1 64 blocks 512B", 64, "sha1", 512, 512},

		{"sha256 100 blocks data512B hash4K", 100, "sha256", 512, 4096},
		{"sha256 200 blocks data4K hash512B", 200, "sha256", 4096, 512},
		{"sha512 50 blocks data512B hash4K", 50, "sha512", 512, 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vh := NewCryptHash(
				tt.hashAlgo,
				tt.dataBlockSize, tt.hashBlockSize,
				tt.dataBlocks,
				1,
				nil, 0,
				"", "",
				nil,
			)

			calculatedSize, err := vh.GetHashTreeSize()
			if err != nil {
				t.Fatalf("CalculateHashTreeSize failed: %v", err)
			}

			levels, err := vh.hashLevels(tt.dataBlocks)
			if err != nil {
				t.Fatalf("hashLevels failed: %v", err)
			}

			expectedBlocks := uint64(0)
			for _, level := range levels {
				expectedBlocks += level.numBlocks
			}
			expectedSize := expectedBlocks * uint64(tt.hashBlockSize)

			if calculatedSize != expectedSize {
				t.Errorf("Size mismatch: calculated=%d, expected=%d", calculatedSize, expectedSize)
			}
		})
	}
}
