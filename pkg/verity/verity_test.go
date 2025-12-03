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
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/containerd/go-dmverity/pkg/utils"
)

func TestGetHashSize(t *testing.T) {
	tests := []struct {
		name     string
		hashName string
		expected int
	}{
		{"sha1", "sha1", 20},
		{"sha256", "sha256", 32},
		{"sha512", "sha512", 64},
		{"SHA256 uppercase", "SHA256", 32},
		{"sha256 with spaces", "  sha256  ", 32},
		{"unsupported", "md5", -1},
		{"empty", "", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utils.SelectHashSize(tt.hashName)
			if result != tt.expected {
				t.Errorf("SelectHashSize(%q) = %d, want %d", tt.hashName, result, tt.expected)
			}
		})
	}
}

func TestUint64MultOverflow(t *testing.T) {
	tests := []struct {
		name     string
		a        uint64
		b        uint64
		overflow bool
	}{
		{"no overflow small", 100, 200, false},
		{"no overflow zero", 0, 1000, false},
		{"no overflow one", 1, 1000, false},
		{"overflow max", ^uint64(0), 2, true},
		{"overflow large", ^uint64(0) / 2, 3, true},
		{"no overflow max by 1", ^uint64(0), 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utils.Uint64MultOverflow(tt.a, tt.b)
			if result != tt.overflow {
				t.Errorf("uint64MultOverflow(%d, %d) = %v, want %v", tt.a, tt.b, result, tt.overflow)
			}
		})
	}
}

func TestWriteSuperblockErrors(t *testing.T) {
	tests := []struct {
		name        string
		params      *Params
		uuid        string
		expectError bool
	}{
		{"nil params", nil, "550e8400-e29b-41d4-a716-446655440000", true},
		{"no superblock", &Params{NoSuperblock: true}, "550e8400-e29b-41d4-a716-446655440000", true},
		{"invalid uuid", &Params{DataBlocks: 100}, "invalid-uuid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "verity-test-*.img")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())
			defer tmpFile.Close()

			var testErr error
			if tt.params == nil {
				testErr = errors.New("verity: nil params")
			} else if tt.params.NoSuperblock {
				testErr = errors.New("verity: device does not use on-disk header")
			} else if tt.uuid == "" {
				testErr = errors.New("verity: UUID required")
			} else {
				parsedUUID, err := uuid.Parse(tt.uuid)
				if err != nil {
					testErr = fmt.Errorf("verity: wrong UUID format: %w", err)
				} else {
					copy(tt.params.UUID[:], parsedUUID[:])
					sb, err := buildSuperblockFromParams(tt.params)
					if err != nil {
						testErr = err
					} else {
						testErr = sb.WriteSuperblock(tmpFile, 0)
					}
				}
			}

			if (testErr != nil) != tt.expectError {
				t.Errorf("WriteSuperblock() error = %v, expectError %v", testErr, tt.expectError)
			}
		})
	}
}

func TestReadSuperblockErrors(t *testing.T) {
	tests := []struct {
		name        string
		params      *Params
		offset      uint64
		expectError bool
	}{
		{"nil params", nil, 0, true},
		{"no superblock", &Params{NoSuperblock: true}, 0, true},
		{"unaligned offset", &Params{}, 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "verity-test-*.img")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())
			defer tmpFile.Close()

			var testErr error
			if tt.params == nil {
				testErr = errors.New("verity: nil params")
			} else if tt.params.NoSuperblock {
				testErr = errors.New("verity: device does not use on-disk header")
			} else if tt.offset%diskSectorSize != 0 {
				testErr = errors.New("verity: unsupported hash offset (not 512-byte aligned)")
			} else {
				sb, err := ReadSuperblock(tmpFile, tt.offset)
				if err != nil {
					testErr = err
				} else {
					testErr = adoptParamsFromSuperblock(tt.params, sb, tt.offset)
				}
			}

			if (testErr != nil) != tt.expectError {
				t.Errorf("ReadSuperblock() error = %v, expectError %v", testErr, tt.expectError)
			}
		})
	}
}

func TestSuperblockRoundTrip(t *testing.T) {
	dataPath, _ := createTestDataFile(t, 4096, 16)
	defer os.Remove(dataPath)

	hashPath := createTestHashFile(t, int64(4096*16*4))
	defer os.Remove(hashPath)

	uuidStr := uuid.New().String()

	salt := []byte("superblock-test")
	params := &Params{
		HashName:       "sha256",
		DataBlockSize:  4096,
		HashBlockSize:  4096,
		DataBlocks:     16,
		HashType:       1,
		Salt:           salt,
		SaltSize:       uint16(len(salt)),
		HashAreaOffset: 0,
		NoSuperblock:   false,
	}

	parsedUUID, _ := uuid.Parse(uuidStr)
	copy(params.UUID[:], parsedUUID[:])

	hashFile, err := os.OpenFile(hashPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("Failed to open hash file: %v", err)
	}

	sb, err := buildSuperblockFromParams(params)
	if err != nil {
		t.Fatalf("buildSuperblockFromParams failed: %v", err)
	}
	err = sb.WriteSuperblock(hashFile, 0)
	hashFile.Close()
	if err != nil {
		t.Fatalf("WriteSuperblock failed: %v", err)
	}

	hashFile2, err := os.Open(hashPath)
	if err != nil {
		t.Fatalf("Failed to open hash file for reading: %v", err)
	}
	defer hashFile2.Close()

	readParams := &Params{}
	sbRead, err := ReadSuperblock(hashFile2, 0)
	if err != nil {
		t.Fatalf("ReadSuperblock failed: %v", err)
	}

	if err := adoptParamsFromSuperblock(readParams, sbRead, 0); err != nil {
		t.Fatalf("adoptParamsFromSuperblock failed: %v", err)
	}

	readUUID, err := sbRead.UUIDString()
	if err != nil {
		t.Fatalf("UUIDString failed: %v", err)
	}

	if !strings.EqualFold(readUUID, uuidStr) {
		t.Errorf("UUID mismatch: written=%s, read=%s", uuidStr, readUUID)
	}
	if readParams.HashName != params.HashName {
		t.Errorf("HashName mismatch: %s != %s", readParams.HashName, params.HashName)
	}
	if readParams.DataBlockSize != params.DataBlockSize {
		t.Errorf("DataBlockSize mismatch: %d != %d", readParams.DataBlockSize, params.DataBlockSize)
	}
	if readParams.HashBlockSize != params.HashBlockSize {
		t.Errorf("HashBlockSize mismatch: %d != %d", readParams.HashBlockSize, params.HashBlockSize)
	}
	if readParams.DataBlocks != params.DataBlocks {
		t.Errorf("DataBlocks mismatch: %d != %d", readParams.DataBlocks, params.DataBlocks)
	}
	if !bytes.Equal(readParams.Salt, params.Salt) {
		t.Errorf("Salt mismatch")
	}
}

func TestCreateWithVeritysetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping integration test")
	}

	tests := []struct {
		name         string
		numBlocks    uint64
		hashAlgo     string
		useSalt      bool
		noSuperblock bool
	}{
		{"basic sha256 no salt", 16, "sha256", false, true},
		{"sha256 with salt", 32, "sha256", true, true},
		{"sha512 no salt", 16, "sha512", false, true},
		{"sha1 with salt", 8, "sha1", true, true},
		{"superblock sha256 no salt", 16, "sha256", false, false},
		{"superblock sha256 with salt", 32, "sha256", true, false},
		{"superblock sha512 no salt", 16, "sha512", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPathGo := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathGo)

			hashPathC := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathC)

			var salt []byte
			saltArgs := []string{"--salt", "-"}
			if tt.useSalt {
				salt = []byte("integration-test-salt")
				saltArgs = []string{"--salt", hex.EncodeToString(salt)}
			}

			params := &Params{
				HashName:       tt.hashAlgo,
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     tt.numBlocks,
				HashType:       1,
				Salt:           salt,
				SaltSize:       uint16(len(salt)),
				HashAreaOffset: 0,
				NoSuperblock:   tt.noSuperblock,
			}

			var rootHashGo []byte
			var err error

			if tt.noSuperblock {
				rootHashGo, err = Create(params, dataPath, hashPathGo)
				if err != nil {
					t.Fatalf("Create failed: %v", err)
				}
			} else {
				uuidStr := uuid.New().String()
				params.HashAreaOffset = 4096
				parsedUUID, _ := uuid.Parse(uuidStr)
				copy(params.UUID[:], parsedUUID[:])

				hashFile, _ := os.OpenFile(hashPathGo, os.O_RDWR, 0)
				parsedUUID2, _ := uuid.Parse(uuidStr)
				copy(params.UUID[:], parsedUUID2[:])
				sb, _ := buildSuperblockFromParams(params)
				if err := sb.WriteSuperblock(hashFile, 0); err != nil {
					t.Fatalf("Failed to write superblock: %v", err)
				}
				hashFile.Close()

				rootHashGo, err = Create(params, dataPath, hashPathGo)
				if err != nil {
					t.Fatalf("Create failed: %v", err)
				}
			}

			args := []string{"format", dataPath, hashPathC, "--hash", tt.hashAlgo,
				"--data-block-size", "4096", "--hash-block-size", "4096"}
			args = append(args, saltArgs...)
			if tt.noSuperblock {
				args = append(args, "--no-superblock")
			}

			cmd := exec.Command("veritysetup", args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("veritysetup format failed: %v\nOutput: %s", err, string(output))
			}

			rootHashC := extractRootHash(t, string(output))
			rootHashCBytes, _ := hex.DecodeString(rootHashC)

			if !bytes.Equal(rootHashGo, rootHashCBytes) {
				t.Errorf("Root hash mismatch:\nGo: %x\nveritysetup: %x", rootHashGo, rootHashCBytes)
			}
		})
	}
}

func TestVerifyWithVeritysetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping integration test")
	}

	tests := []struct {
		name         string
		numBlocks    uint64
		hashAlgo     string
		useSalt      bool
		noSuperblock bool
	}{
		{"verify sha256", 16, "sha256", true, true},
		{"verify sha512", 8, "sha512", false, true},
		{"verify superblock sha256", 16, "sha256", true, false},
		{"verify superblock sha512", 8, "sha512", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPath := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPath)

			var salt []byte
			if tt.useSalt {
				salt = []byte("verify-test-salt")
			}

			params := &Params{
				HashName:       tt.hashAlgo,
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     tt.numBlocks,
				HashType:       1,
				Salt:           salt,
				SaltSize:       uint16(len(salt)),
				HashAreaOffset: 0,
				NoSuperblock:   tt.noSuperblock,
			}

			var rootHash []byte
			var err error

			if tt.noSuperblock {
				rootHash, err = Create(params, dataPath, hashPath)
			} else {
				uuidStr := uuid.New().String()
				params.HashAreaOffset = 4096
				parsedUUID, _ := uuid.Parse(uuidStr)
				copy(params.UUID[:], parsedUUID[:])

				hashFile, _ := os.OpenFile(hashPath, os.O_RDWR, 0)
				parsedUUID2, _ := uuid.Parse(uuidStr)
				copy(params.UUID[:], parsedUUID2[:])
				sb, _ := buildSuperblockFromParams(params)
				if err := sb.WriteSuperblock(hashFile, 0); err != nil {
					t.Fatalf("Failed to write superblock: %v", err)
				}
				hashFile.Close()

				rootHash, err = Create(params, dataPath, hashPath)
			}

			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			if err := Verify(params, dataPath, hashPath, rootHash); err != nil {
				t.Errorf("Verify failed: %v", err)
			}
		})
	}
}

func TestCrossVerificationWithVeritysetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping cross-verification test")
	}

	tests := []struct {
		name      string
		numBlocks uint64
		hashAlgo  string
		useSalt   bool
	}{
		{"sha256 no salt", 16, "sha256", false},
		{"sha256 with salt", 16, "sha256", true},
		{"sha512 no salt", 8, "sha512", false},
		{"sha512 with salt", 8, "sha512", true},
		{"sha1 no salt", 8, "sha1", false},
		{"sha1 with salt", 8, "sha1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPathGo := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathGo)

			hashPathC := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathC)

			var salt []byte
			saltArgs := []string{"--salt", "-"}
			if tt.useSalt {
				salt = []byte("cross-verify-salt")
				saltArgs = []string{"--salt", hex.EncodeToString(salt)}
			}

			params := &Params{
				HashName:       tt.hashAlgo,
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     tt.numBlocks,
				HashType:       1,
				Salt:           salt,
				SaltSize:       uint16(len(salt)),
				HashAreaOffset: 0,
				NoSuperblock:   true,
			}

			rootHashGo, _ := Create(params, dataPath, hashPathGo)

			args := []string{"format", dataPath, hashPathC, "--hash", tt.hashAlgo,
				"--data-block-size", "4096", "--hash-block-size", "4096"}
			args = append(args, saltArgs...)

			cmd := exec.Command("veritysetup", args...)
			output, _ := cmd.CombinedOutput()
			rootHashC := extractRootHash(t, string(output))
			rootHashCBytes, _ := hex.DecodeString(rootHashC)

			if !bytes.Equal(rootHashGo, rootHashCBytes) {
				t.Errorf("Root hash mismatch: Go=%x, veritysetup=%x", rootHashGo, rootHashCBytes)
			}

			hashContent, _ := os.ReadFile(hashPathC)
			if len(hashContent) > 4096 {
				hashTreeOnly := hashContent[4096:]
				hashPathStripped := createTestHashFile(t, int64(len(hashTreeOnly)))
				defer os.Remove(hashPathStripped)
				if err := os.WriteFile(hashPathStripped, hashTreeOnly, 0644); err != nil {
					t.Fatalf("Failed to write stripped hash file: %v", err)
				}

				if err := Verify(params, dataPath, hashPathStripped, rootHashCBytes); err != nil {
					t.Errorf("Go failed to verify veritysetup hash tree: %v", err)
				}
			}

			if err := Verify(params, dataPath, hashPathGo, rootHashGo); err != nil {
				t.Errorf("Go failed to verify its own hash tree: %v", err)
			}
		})
	}
}

func TestDataCorruptionDetection(t *testing.T) {
	tests := []struct {
		name      string
		hashAlgo  string
		numBlocks uint64
		useSalt   bool
	}{
		{"sha256 no salt", "sha256", 16, false},
		{"sha256 with salt", "sha256", 16, true},
		{"sha512", "sha512", 8, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPath := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPath)

			var salt []byte
			if tt.useSalt {
				salt = []byte("corruption-test-salt")
			}

			params := &Params{
				HashName:       tt.hashAlgo,
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     tt.numBlocks,
				HashType:       1,
				Salt:           salt,
				SaltSize:       uint16(len(salt)),
				HashAreaOffset: 0,
				NoSuperblock:   true,
			}

			rootHash, _ := Create(params, dataPath, hashPath)

			if err := Verify(params, dataPath, hashPath, rootHash); err != nil {
				t.Fatalf("Initial verification failed: %v", err)
			}

			dataFile, _ := os.OpenFile(dataPath, os.O_RDWR, 0)
			if _, err := dataFile.WriteAt([]byte{0xFF, 0xFF, 0xFF, 0xFF}, 0); err != nil {
				t.Fatalf("Failed to write corrupted data: %v", err)
			}
			dataFile.Close()

			if err := Verify(params, dataPath, hashPath, rootHash); err == nil {
				t.Error("Verification should fail with corrupted data")
			}

			dataPath2, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath2)
			hashPath2 := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPath2)

			rootHash2, _ := Create(params, dataPath2, hashPath2)

			dataFile2, _ := os.OpenFile(dataPath2, os.O_RDWR, 0)
			if _, err := dataFile2.WriteAt([]byte{0xAA, 0xBB, 0xCC, 0xDD}, int64(tt.numBlocks/2)*4096); err != nil {
				t.Fatalf("Failed to write corrupted data: %v", err)
			}
			dataFile2.Close()

			if err := Verify(params, dataPath2, hashPath2, rootHash2); err == nil {
				t.Error("Verification should fail with corrupted middle block")
			}
		})
	}
}

func TestHashTreeCorruptionDetection(t *testing.T) {
	tests := []struct {
		name      string
		hashAlgo  string
		numBlocks uint64
	}{
		{"sha256", "sha256", 16},
		{"sha512", "sha512", 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPath := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPath)

			params := &Params{
				HashName:       tt.hashAlgo,
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     tt.numBlocks,
				HashType:       1,
				Salt:           []byte("hash-corruption-test"),
				SaltSize:       20,
				HashAreaOffset: 0,
				NoSuperblock:   true,
			}

			rootHash, _ := Create(params, dataPath, hashPath)

			if err := Verify(params, dataPath, hashPath, rootHash); err != nil {
				t.Fatalf("Initial verification failed: %v", err)
			}

			hashFile, _ := os.OpenFile(hashPath, os.O_RDWR, 0)
			if _, err := hashFile.WriteAt([]byte{0xFF, 0xFF, 0xFF, 0xFF}, 100); err != nil {
				t.Fatalf("Failed to write corrupted hash: %v", err)
			}
			hashFile.Close()

			if err := Verify(params, dataPath, hashPath, rootHash); err == nil {
				t.Error("Verification should fail with corrupted hash tree")
			}
		})
	}
}

func TestRootHashMismatch(t *testing.T) {
	dataPath, _ := createTestDataFile(t, 4096, 16)
	defer os.Remove(dataPath)

	hashPath := createTestHashFile(t, int64(4096*32))
	defer os.Remove(hashPath)

	params := &Params{
		HashName:       "sha256",
		DataBlockSize:  4096,
		HashBlockSize:  4096,
		DataBlocks:     16,
		HashType:       1,
		Salt:           []byte("mismatch-test"),
		SaltSize:       13,
		HashAreaOffset: 0,
		NoSuperblock:   true,
	}

	_, err := Create(params, dataPath, hashPath)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	wrongRootHash := make([]byte, 32)
	for i := range wrongRootHash {
		wrongRootHash[i] = 0xFF
	}

	err = Verify(params, dataPath, hashPath, wrongRootHash)
	if err == nil {
		t.Error("Verification should fail with wrong root hash")
	}
}

func TestBoundaryConditions(t *testing.T) {
	tests := []struct {
		name      string
		numBlocks uint64
	}{
		{"single block", 1},
		{"two blocks", 2},
		{"large dataset", 512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPath := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*4))
			defer os.Remove(hashPath)

			params := &Params{
				HashName:       "sha256",
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     tt.numBlocks,
				HashType:       1,
				Salt:           []byte("boundary-test"),
				SaltSize:       13,
				HashAreaOffset: 0,
				NoSuperblock:   true,
			}

			rootHash, err := Create(params, dataPath, hashPath)
			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			if err := Verify(params, dataPath, hashPath, rootHash); err != nil {
				t.Errorf("Verification failed: %v", err)
			}
		})
	}
}

func TestGetHashTreeSize(t *testing.T) {
	tests := []struct {
		name          string
		numBlocks     uint64
		hashAlgo      string
		dataBlockSize uint32
		hashBlockSize uint32
	}{
		{"sha256 16 blocks 4K", 16, "sha256", 4096, 4096},
		{"sha256 128 blocks 4K", 128, "sha256", 4096, 4096},
		{"sha256 256 blocks 4K", 256, "sha256", 4096, 4096},
		{"sha512 16 blocks 4K", 16, "sha512", 4096, 4096},
		{"sha512 64 blocks 4K", 64, "sha512", 4096, 4096},
		{"sha1 32 blocks 4K", 32, "sha1", 4096, 4096},

		{"sha256 64 blocks 512B", 64, "sha256", 512, 512},
		{"sha256 128 blocks 512B", 128, "sha256", 512, 512},
		{"sha512 32 blocks 512B", 32, "sha512", 512, 512},
		{"sha1 64 blocks 512B", 64, "sha1", 512, 512},

		{"sha256 100 blocks data512B hash4K", 100, "sha256", 512, 4096},
		{"sha256 200 blocks data4K hash512B", 200, "sha256", 4096, 512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, tt.dataBlockSize, tt.numBlocks)
			defer os.Remove(dataPath)

			params := &Params{
				HashName:       tt.hashAlgo,
				DataBlockSize:  tt.dataBlockSize,
				HashBlockSize:  tt.hashBlockSize,
				DataBlocks:     tt.numBlocks,
				HashType:       1,
				Salt:           []byte("test-salt"),
				SaltSize:       9,
				HashAreaOffset: 0,
				NoSuperblock:   true,
			}

			expectedSize, err := GetHashTreeSize(params)
			if err != nil {
				t.Fatalf("GetHashTreeSize failed: %v", err)
			}

			hashPath := createTestHashFile(t, int64(expectedSize))
			defer os.Remove(hashPath)

			_, err = Create(params, dataPath, hashPath)
			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			hashData, err := os.ReadFile(hashPath)
			if err != nil {
				t.Fatalf("Failed to read hash file: %v", err)
			}

			actualUsed := uint64(0)
			for i := len(hashData) - 1; i >= 0; i-- {
				if hashData[i] != 0 {
					actualUsed = uint64(i + 1)
					break
				}
			}

			if actualUsed > expectedSize {
				t.Errorf("Actual hash data size %d exceeds calculated size %d", actualUsed, expectedSize)
			}

			rootHash, err := Create(params, dataPath, hashPath)
			if err != nil {
				t.Fatalf("Create failed on second run: %v", err)
			}

			if err := Verify(params, dataPath, hashPath, rootHash); err != nil {
				t.Errorf("Verify failed: %v", err)
			}
		})
	}
}

func TestOpen(t *testing.T) {
	tests := []struct {
		name         string
		numBlocks    uint64
		hashAlgo     string
		useSalt      bool
		noSuperblock bool
	}{
		{"sha256 no salt no superblock", 16, "sha256", false, true},
		{"sha256 with salt no superblock", 16, "sha256", true, true},
		{"sha512 no salt no superblock", 8, "sha512", false, true},
		{"sha256 with superblock", 16, "sha256", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPath := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPath)

			var salt []byte
			if tt.useSalt {
				salt = []byte("open-test-salt")
			}

			params := &Params{
				HashName:       tt.hashAlgo,
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     tt.numBlocks,
				HashType:       1,
				Salt:           salt,
				SaltSize:       uint16(len(salt)),
				HashAreaOffset: 0,
				NoSuperblock:   tt.noSuperblock,
			}

			var rootHash []byte
			var err error
			if tt.noSuperblock {
				rootHash, err = Create(params, dataPath, hashPath)
				if err != nil {
					t.Fatalf("Create failed: %v", err)
				}
			} else {
				uuidStr := uuid.New().String()
				params.HashAreaOffset = 4096
				parsedUUID, _ := uuid.Parse(uuidStr)
				copy(params.UUID[:], parsedUUID[:])

				rootHash, err = Create(params, dataPath, hashPath)
				if err != nil {
					t.Fatalf("Create failed: %v", err)
				}
			}

			dataLoop, err := utils.AttachLoopDevice(dataPath)
			if err != nil {
				t.Fatalf("Failed to setup data loop device: %v", err)
			}
			defer func() {
				if err := utils.DetachLoopDevice(dataLoop); err != nil {
					t.Logf("Failed to detach data loop device: %v", err)
				}
			}()

			hashLoop, err := utils.AttachLoopDevice(hashPath)
			if err != nil {
				t.Fatalf("Failed to setup hash loop device: %v", err)
			}
			defer func() {
				if err := utils.DetachLoopDevice(hashLoop); err != nil {
					t.Logf("Failed to detach hash loop device: %v", err)
				}
			}()

			deviceName := fmt.Sprintf("verity-test-%d", os.Getpid())
			devPath, err := Open(params, deviceName, dataLoop, hashLoop, rootHash, "", nil)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer func() {
				if err := Close(deviceName); err != nil {
					t.Logf("Failed to close device: %v", err)
				}
			}()

			if devPath != "/dev/mapper/"+deviceName {
				t.Errorf("Unexpected device path: got %s, want %s", devPath, "/dev/mapper/"+deviceName)
			}

			if _, err := os.Stat(devPath); err != nil {
				t.Errorf("Device path does not exist: %v", err)
			}
		})
	}
}

func TestClose(t *testing.T) {
	dataPath, _ := createTestDataFile(t, 4096, 16)
	defer os.Remove(dataPath)

	hashPath := createTestHashFile(t, int64(4096*16*2))
	defer os.Remove(hashPath)

	dataLoop, err := utils.AttachLoopDevice(dataPath)
	if err != nil {
		t.Fatalf("Failed to setup data loop device: %v", err)
	}
	defer func() {
		if err := utils.DetachLoopDevice(dataLoop); err != nil {
			t.Logf("Failed to detach data loop device: %v", err)
		}
	}()

	hashLoop, err := utils.AttachLoopDevice(hashPath)
	if err != nil {
		t.Fatalf("Failed to setup hash loop device: %v", err)
	}
	defer func() {
		if err := utils.DetachLoopDevice(hashLoop); err != nil {
			t.Logf("Failed to detach hash loop device: %v", err)
		}
	}()

	params := &Params{
		HashName:       "sha256",
		DataBlockSize:  4096,
		HashBlockSize:  4096,
		DataBlocks:     16,
		HashType:       1,
		Salt:           []byte("close-test"),
		SaltSize:       10,
		HashAreaOffset: 0,
		NoSuperblock:   true,
	}

	rootHash, err := Create(params, dataPath, hashPath)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	deviceName := fmt.Sprintf("verity-close-test-%d", os.Getpid())
	devPath, err := Open(params, deviceName, dataLoop, hashLoop, rootHash, "", nil)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if _, err := os.Stat(devPath); err != nil {
		t.Fatalf("Device path does not exist before close: %v", err)
	}

	if err := Close(deviceName); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	if _, err := os.Stat(devPath); err == nil {
		t.Errorf("Device path still exists after close")
	}

	if err := Close(deviceName); err == nil {
		t.Errorf("Close should fail on non-existent device")
	}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name             string
		hashAlgo         string
		checkRootHash    bool
		useWrongRootHash bool
		expectedResult   bool
	}{
		{"sha256 no hash check", "sha256", false, false, true},
		{"sha256 with correct hash", "sha256", true, false, true},
		{"sha256 with wrong hash", "sha256", true, true, false},
		{"sha512 with correct hash", "sha512", true, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, 16)
			defer os.Remove(dataPath)

			hashPath := createTestHashFile(t, int64(4096*16*2))
			defer os.Remove(hashPath)

			dataLoop, err := utils.AttachLoopDevice(dataPath)
			if err != nil {
				t.Fatalf("Failed to setup data loop device: %v", err)
			}
			defer func() {
				if err := utils.DetachLoopDevice(dataLoop); err != nil {
					t.Logf("Failed to detach data loop device: %v", err)
				}
			}()

			hashLoop, err := utils.AttachLoopDevice(hashPath)
			if err != nil {
				t.Fatalf("Failed to setup hash loop device: %v", err)
			}
			defer func() {
				if err := utils.DetachLoopDevice(hashLoop); err != nil {
					t.Logf("Failed to detach hash loop device: %v", err)
				}
			}()

			params := &Params{
				HashName:       tt.hashAlgo,
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     16,
				HashType:       1,
				Salt:           []byte("check-test"),
				SaltSize:       10,
				HashAreaOffset: 0,
				NoSuperblock:   true,
			}

			rootHash, err := Create(params, dataPath, hashPath)
			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			deviceName := fmt.Sprintf("verity-check-test-%d", os.Getpid())
			_, err = Open(params, deviceName, dataLoop, hashLoop, rootHash, "", nil)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer func() {
				if err := Close(deviceName); err != nil {
					t.Logf("Failed to close verity device: %v", err)
				}
			}()

			var checkHash []byte
			if tt.checkRootHash {
				if tt.useWrongRootHash {
					checkHash = make([]byte, len(rootHash))
					for i := range checkHash {
						checkHash[i] = ^rootHash[i]
					}
				} else {
					checkHash = rootHash
				}
			}

			result := Check(deviceName, checkHash)
			if result != tt.expectedResult {
				t.Errorf("Check() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}
