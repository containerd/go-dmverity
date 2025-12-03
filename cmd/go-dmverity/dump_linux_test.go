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
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/containerd/go-dmverity/pkg/utils"
	"github.com/containerd/go-dmverity/pkg/verity"
)

func TestDump(t *testing.T) {
	utils.RequireTool(t, "veritysetup")

	tests := []struct {
		name     string
		hashAlgo string
		useSalt  bool
	}{
		{"sha256 no salt", "sha256", false},
		{"sha256 with salt", "sha256", true},
		{"sha512 no salt", "sha512", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := utils.MakeTempFile(t, 4096*16)
			hash := utils.MakeTempFile(t, 0)
			defer os.Remove(data)
			defer os.Remove(hash)

			args := []string{"format", data, hash, "--hash", tt.hashAlgo}
			if tt.useSalt {
				args = append(args, "--salt", "0102030405060708")
			} else {
				args = append(args, "--salt", "-")
			}

			cmd := exec.Command("veritysetup", args...)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("veritysetup format failed: %v\n%s", err, output)
			}

			cmd = exec.Command("veritysetup", "dump", hash)
			veritysetupOutput, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("veritysetup dump failed: %v\n%s", err, veritysetupOutput)
			}

			goOutput, _ := utils.RunGoCLI(t, "dump", hash)

			veritysetupStr := string(veritysetupOutput)
			compareField(t, "Hash type", veritysetupStr, goOutput)
			compareField(t, "Data blocks", veritysetupStr, goOutput)
			compareField(t, "Data block size", veritysetupStr, goOutput)
			compareField(t, "Hash blocks", veritysetupStr, goOutput)
			compareField(t, "Hash block size", veritysetupStr, goOutput)
			compareField(t, "Hash algorithm", veritysetupStr, goOutput)
			compareField(t, "Salt", veritysetupStr, goOutput)
			compareField(t, "Hash device size", veritysetupStr, goOutput)
		})
	}
}

func TestDump_NoSuperblock(t *testing.T) {
	data := utils.MakeTempFile(t, 4096*16)
	hash := utils.MakeTempFile(t, 0)
	defer os.Remove(data)
	defer os.Remove(hash)

	params := verity.DefaultParams()
	params.NoSuperblock = true
	params.DataBlocks = 16
	params.DataBlockSize = 4096
	params.HashBlockSize = 4096

	_, err := verity.Create(&params, data, hash)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err = runDump(hash)
	if err == nil {
		t.Error("dump should fail for hash device without superblock")
	}
	if !strings.Contains(err.Error(), "superblock") {
		t.Errorf("error should mention superblock, got: %v", err)
	}
}

func TestDump_InvalidDevice(t *testing.T) {
	err := runDump("/nonexistent/device")
	if err == nil {
		t.Error("dump should fail for nonexistent device")
	}
}

func TestDump_CorruptedSuperblock(t *testing.T) {
	hash := utils.MakeTempFile(t, 4096)
	defer os.Remove(hash)

	f, _ := os.OpenFile(hash, os.O_WRONLY, 0644)
	if _, err := f.Write(make([]byte, 4096)); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}
	f.Close()

	err := runDump(hash)
	if err == nil {
		t.Error("dump should fail for corrupted superblock")
	}
}

func TestParseDumpArgs_InvalidArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no args", []string{}},
		{"too many args", []string{"hash1", "hash2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseDumpArgs(tt.args)
			if err == nil {
				t.Error("parseDumpArgs should fail with invalid args")
			}
		})
	}
}

func compareField(t *testing.T, field, veritysetupOutput, goOutput string) {
	t.Helper()

	veritysetupValue := extractFieldValue(veritysetupOutput, field)
	goValue := extractFieldValue(goOutput, field)

	if veritysetupValue == "" {
		t.Logf("Warning: field '%s' not found in veritysetup output", field)
		return
	}

	if goValue == "" {
		t.Errorf("field '%s' not found in Go output", field)
		return
	}

	if veritysetupValue != goValue {
		t.Errorf("field '%s' mismatch:\n  veritysetup: %s\n  Go:          %s",
			field, veritysetupValue, goValue)
	}
}

func extractFieldValue(output, field string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, field) {
			parts := strings.Split(line, "\t")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[len(parts)-1])
			}
		}
	}
	return ""
}
