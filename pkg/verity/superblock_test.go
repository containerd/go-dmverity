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
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
)

type mockReaderAt struct {
	data []byte
	err  error
}

func (m *mockReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	if off < 0 || off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n = copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

type mockWriterAt struct {
	data []byte
	err  error
}

func (m *mockWriterAt) WriteAt(p []byte, off int64) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if int(off)+len(p) > len(m.data) {
		return 0, io.ErrShortWrite
	}
	n = copy(m.data[off:], p)
	return n, nil
}

func createValidSuperblock(t *testing.T) *Superblock {
	t.Helper()
	sb := DefaultSuperblock()

	testUUID := uuid.New()
	copy(sb.UUID[:], testUUID[:])

	sb.DataBlocks = 1024
	sb.SaltSize = 32
	for i := 0; i < 32; i++ {
		sb.Salt[i] = byte(i)
	}

	return &sb
}

func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

func TestReadSuperblock(t *testing.T) {
	tests := []struct {
		name      string
		setupData func() (io.ReaderAt, uint64)
		wantErr   bool
		errMsg    string
	}{
		{
			name: "valid superblock at offset 0",
			setupData: func() (io.ReaderAt, uint64) {
				sb := createValidSuperblock(t)
				data, err := sb.Serialize()
				if err != nil {
					t.Fatalf("failed to serialize superblock: %v", err)
				}
				if len(data) < SuperblockSize {
					data = append(data, make([]byte, SuperblockSize-len(data))...)
				}
				return &mockReaderAt{data: data}, 0
			},
			wantErr: false,
		},
		{
			name: "valid superblock at offset 512",
			setupData: func() (io.ReaderAt, uint64) {
				sb := createValidSuperblock(t)
				data, err := sb.Serialize()
				if err != nil {
					t.Fatalf("failed to serialize superblock: %v", err)
				}
				paddedData := make([]byte, 512+SuperblockSize)
				copy(paddedData[512:], data)
				return &mockReaderAt{data: paddedData}, 512
			},
			wantErr: false,
		},
		{
			name: "unaligned offset",
			setupData: func() (io.ReaderAt, uint64) {
				return &mockReaderAt{data: make([]byte, 1024)}, 100
			},
			wantErr: true,
			errMsg:  "not 512-byte aligned",
		},
		{
			name: "superblock with empty UUID",
			setupData: func() (io.ReaderAt, uint64) {
				sb := DefaultSuperblock()
				sb.DataBlocks = 1024
				data, err := sb.Serialize()
				if err != nil {
					t.Fatalf("failed to serialize superblock: %v", err)
				}
				return &mockReaderAt{data: data}, 0
			},
			wantErr: true,
			errMsg:  "missing UUID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, offset := tt.setupData()
			sb, err := ReadSuperblock(reader, offset)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ReadSuperblock() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("ReadSuperblock() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("ReadSuperblock() unexpected error = %v", err)
				return
			}

			if sb == nil {
				t.Error("ReadSuperblock() returned nil superblock")
			}
		})
	}
}

func TestWriteSuperblock(t *testing.T) {
	tests := []struct {
		name      string
		setupTest func() (*Superblock, io.WriterAt, uint64)
		wantErr   bool
		errMsg    string
	}{
		{
			name: "write at offset 0",
			setupTest: func() (*Superblock, io.WriterAt, uint64) {
				sb := createValidSuperblock(t)
				writer := &mockWriterAt{data: make([]byte, 1024)}
				return sb, writer, 0
			},
			wantErr: false,
		},
		{
			name: "write at offset 512",
			setupTest: func() (*Superblock, io.WriterAt, uint64) {
				sb := createValidSuperblock(t)
				writer := &mockWriterAt{data: make([]byte, 2048)}
				return sb, writer, 512
			},
			wantErr: false,
		},
		{
			name: "unaligned offset",
			setupTest: func() (*Superblock, io.WriterAt, uint64) {
				sb := createValidSuperblock(t)
				writer := &mockWriterAt{data: make([]byte, 1024)}
				return sb, writer, 100
			},
			wantErr: true,
			errMsg:  "not 512-byte aligned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb, writer, offset := tt.setupTest()
			err := sb.WriteSuperblock(writer, offset)

			if tt.wantErr {
				if err == nil {
					t.Errorf("WriteSuperblock() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("WriteSuperblock() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("WriteSuperblock() unexpected error = %v", err)
			}
		})
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	original := createValidSuperblock(t)

	buffer := make([]byte, 2048)
	writer := &mockWriterAt{data: buffer}

	offset := uint64(512)
	if err := original.WriteSuperblock(writer, offset); err != nil {
		t.Fatalf("WriteSuperblock() failed: %v", err)
	}

	reader := &mockReaderAt{data: buffer}
	readBack, err := ReadSuperblock(reader, offset)
	if err != nil {
		t.Fatalf("ReadSuperblock() failed: %v", err)
	}

	verifySuperblockFields(t, original, readBack)
}

func verifySuperblockFields(t *testing.T, expected, actual *Superblock) {
	t.Helper()
	if !bytes.Equal(expected.Signature[:], actual.Signature[:]) {
		t.Error("Signature mismatch")
	}
	if expected.Version != actual.Version {
		t.Errorf("Version mismatch: got %d, want %d", actual.Version, expected.Version)
	}
	if expected.HashType != actual.HashType {
		t.Errorf("HashType mismatch: got %d, want %d", actual.HashType, expected.HashType)
	}
	if !bytes.Equal(expected.UUID[:], actual.UUID[:]) {
		t.Error("UUID mismatch")
	}
	if !bytes.Equal(expected.Algorithm[:], actual.Algorithm[:]) {
		t.Error("Algorithm mismatch")
	}
	if expected.DataBlockSize != actual.DataBlockSize {
		t.Errorf("DataBlockSize mismatch: got %d, want %d", actual.DataBlockSize, expected.DataBlockSize)
	}
	if expected.HashBlockSize != actual.HashBlockSize {
		t.Errorf("HashBlockSize mismatch: got %d, want %d", actual.HashBlockSize, expected.HashBlockSize)
	}
	if expected.DataBlocks != actual.DataBlocks {
		t.Errorf("DataBlocks mismatch: got %d, want %d", actual.DataBlocks, expected.DataBlocks)
	}
	if expected.SaltSize != actual.SaltSize {
		t.Errorf("SaltSize mismatch: got %d, want %d", actual.SaltSize, expected.SaltSize)
	}
	if !bytes.Equal(expected.Salt[:], actual.Salt[:]) {
		t.Error("Salt mismatch")
	}
}

func validParams(hashName string, saltSize uint16) *Params {
	return &Params{
		HashName:      hashName,
		DataBlockSize: 4096,
		HashBlockSize: 4096,
		DataBlocks:    1000,
		HashType:      1,
		Salt:          make([]byte, saltSize),
		SaltSize:      saltSize,
		UUID:          uuid.New(),
	}
}

func TestBuildSuperblockFromParams(t *testing.T) {
	tests := []struct {
		name    string
		params  *Params
		wantErr bool
		errMsg  string
		verify  func(*testing.T, *Superblock)
	}{
		{"nil params", nil, true, "nil params", nil},
		{
			name:    "valid params with sha256",
			params:  validParams("sha256", 32),
			wantErr: false,
			verify: func(t *testing.T, sb *Superblock) {
				if sb.Version != 1 || sb.DataBlockSize != 4096 || sb.HashBlockSize != 4096 ||
					sb.DataBlocks != 1000 || sb.SaltSize != 32 {
					t.Error("Superblock fields mismatch")
				}
				if sb.algorithmString() != "sha256" {
					t.Errorf("Algorithm = %q, want sha256", sb.algorithmString())
				}
			},
		},
		{
			name:    "valid params with sha512",
			params:  validParams("sha512", 64),
			wantErr: false,
			verify: func(t *testing.T, sb *Superblock) {
				if sb.algorithmString() != "sha512" {
					t.Errorf("Algorithm = %q, want sha512", sb.algorithmString())
				}
			},
		},
		{
			name: "valid params with empty UUID",
			params: &Params{
				HashName: "sha256", DataBlockSize: 4096, HashBlockSize: 4096,
				DataBlocks: 1000, HashType: 1, Salt: make([]byte, 32), SaltSize: 32,
				UUID: [16]byte{},
			},
			wantErr: false,
			verify: func(t *testing.T, sb *Superblock) {
				if sb.UUID != ([16]byte{}) {
					t.Error("UUID should be empty")
				}
			},
		},
		{
			name: "invalid data block size",
			params: &Params{
				HashName: "sha256", DataBlockSize: 1000, HashBlockSize: 4096,
				DataBlocks: 100, HashType: 1, Salt: make([]byte, 32), SaltSize: 32, UUID: uuid.New(),
			},
			wantErr: true,
			errMsg:  "invalid block sizes",
		},
		{
			name: "invalid hash block size",
			params: &Params{
				HashName: "sha256", DataBlockSize: 4096, HashBlockSize: 3000,
				DataBlocks: 100, HashType: 1, Salt: make([]byte, 32), SaltSize: 32, UUID: uuid.New(),
			},
			wantErr: true,
			errMsg:  "invalid block sizes",
		},
		{
			name: "unsupported hash type",
			params: &Params{
				HashName: "sha256", DataBlockSize: 4096, HashBlockSize: 4096,
				DataBlocks: 100, HashType: 99, Salt: make([]byte, 32), SaltSize: 32, UUID: uuid.New(),
			},
			wantErr: true,
			errMsg:  "unsupported hash type",
		},
		{
			name: "salt size mismatch",
			params: &Params{
				HashName: "sha256", DataBlockSize: 4096, HashBlockSize: 4096,
				DataBlocks: 100, HashType: 1, Salt: make([]byte, 32), SaltSize: 64, UUID: uuid.New(),
			},
			wantErr: true,
			errMsg:  "salt size mismatch",
		},
		{
			name: "salt too large",
			params: &Params{
				HashName: "sha256", DataBlockSize: 4096, HashBlockSize: 4096,
				DataBlocks: 100, HashType: 1, Salt: make([]byte, 300), SaltSize: 300, UUID: uuid.New(),
			},
			wantErr: true,
			errMsg:  "salt too large",
		},
		{
			name: "empty hash algorithm",
			params: &Params{
				HashName: "", DataBlockSize: 4096, HashBlockSize: 4096,
				DataBlocks: 100, HashType: 1, Salt: make([]byte, 32), SaltSize: 32, UUID: uuid.New(),
			},
			wantErr: true,
			errMsg:  "hash algorithm required",
		},
		{
			name: "unsupported hash algorithm",
			params: &Params{
				HashName: "md5", DataBlockSize: 4096, HashBlockSize: 4096,
				DataBlocks: 100, HashType: 1, Salt: make([]byte, 32), SaltSize: 32, UUID: uuid.New(),
			},
			wantErr: true,
			errMsg:  "not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb, err := buildSuperblockFromParams(tt.params)

			if tt.wantErr {
				if err == nil {
					t.Errorf("buildSuperblockFromParams() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("buildSuperblockFromParams() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("buildSuperblockFromParams() unexpected error = %v", err)
				return
			}

			if sb == nil {
				t.Error("buildSuperblockFromParams() returned nil superblock")
				return
			}

			if string(sb.Signature[:]) != VeritySignature {
				t.Error("Invalid signature in built superblock")
			}

			if tt.verify != nil {
				tt.verify(t, sb)
			}
		})
	}
}

func TestAdoptParamsFromSuperblock(t *testing.T) {
	createMismatchTest := func(name, errMsg string, modifyParams func(*Params)) struct {
		name      string
		setupTest func() (*Params, *Superblock, uint64)
		wantErr   bool
		errMsg    string
		verify    func(*testing.T, *Params)
	} {
		return struct {
			name      string
			setupTest func() (*Params, *Superblock, uint64)
			wantErr   bool
			errMsg    string
			verify    func(*testing.T, *Params)
		}{
			name: name,
			setupTest: func() (*Params, *Superblock, uint64) {
				sb := createValidSuperblock(t)
				params := &Params{}
				modifyParams(params)
				return params, sb, 0
			},
			wantErr: true,
			errMsg:  errMsg,
		}
	}

	createInvalidSBTest := func(name, errMsg string, modifySB func(*Superblock)) struct {
		name      string
		setupTest func() (*Params, *Superblock, uint64)
		wantErr   bool
		errMsg    string
		verify    func(*testing.T, *Params)
	} {
		return struct {
			name      string
			setupTest func() (*Params, *Superblock, uint64)
			wantErr   bool
			errMsg    string
			verify    func(*testing.T, *Params)
		}{
			name: name,
			setupTest: func() (*Params, *Superblock, uint64) {
				sb := createValidSuperblock(t)
				modifySB(sb)
				return &Params{}, sb, 0
			},
			wantErr: true,
			errMsg:  errMsg,
		}
	}

	tests := []struct {
		name      string
		setupTest func() (*Params, *Superblock, uint64)
		wantErr   bool
		errMsg    string
		verify    func(*testing.T, *Params)
	}{
		{
			name: "nil params",
			setupTest: func() (*Params, *Superblock, uint64) {
				return nil, createValidSuperblock(t), 0
			},
			wantErr: true,
			errMsg:  "nil params",
		},
		{
			name: "nil superblock",
			setupTest: func() (*Params, *Superblock, uint64) {
				return &Params{}, nil, 0
			},
			wantErr: true,
			errMsg:  "nil params or superblock",
		},
		{
			name: "matching params and superblock",
			setupTest: func() (*Params, *Superblock, uint64) {
				sb := createValidSuperblock(t)
				params := &Params{
					HashName: "sha256", DataBlockSize: 4096, HashBlockSize: 4096,
					DataBlocks: 1024, HashType: 1, Salt: make([]byte, 32), SaltSize: 32, UUID: sb.UUID,
				}
				copy(params.Salt, sb.Salt[:32])
				return params, sb, 512
			},
			wantErr: false,
		},
		{
			name: "adopt from superblock with empty UUID",
			setupTest: func() (*Params, *Superblock, uint64) {
				sb := DefaultSuperblock()
				sb.DataBlocks = 1024
				sb.SaltSize = 32
				for i := 0; i < 32; i++ {
					sb.Salt[i] = byte(i)
				}
				return &Params{}, &sb, 512
			},
			wantErr: false,
			verify: func(t *testing.T, p *Params) {
				if p.UUID != ([16]byte{}) {
					t.Error("UUID should be empty")
				}
			},
		},
		createMismatchTest("algorithm mismatch", "algorithm mismatch", func(p *Params) {
			p.HashName = "sha512"
		}),
		createMismatchTest("data block size mismatch", "data block size mismatch", func(p *Params) {
			p.DataBlockSize = 8192
		}),
		createMismatchTest("hash block size mismatch", "hash block size mismatch", func(p *Params) {
			p.HashBlockSize = 8192
		}),
		createMismatchTest("data blocks mismatch", "data blocks mismatch", func(p *Params) {
			p.DataBlocks = 2048
		}),
		createMismatchTest("salt mismatch", "salt mismatch", func(p *Params) {
			p.Salt = make([]byte, 32)
			p.SaltSize = 32
			for i := range p.Salt {
				p.Salt[i] = 0xFF
			}
		}),
		createMismatchTest("UUID mismatch", "UUID mismatch", func(p *Params) {
			p.UUID = uuid.New()
		}),
		createInvalidSBTest("invalid superblock signature", "invalid superblock signature", func(sb *Superblock) {
			sb.Signature = [8]byte{}
		}),
		createInvalidSBTest("invalid superblock version", "unsupported superblock version", func(sb *Superblock) {
			sb.Version = 99
		}),
		createInvalidSBTest("unsupported hash type in superblock", "unsupported hash type", func(sb *Superblock) {
			sb.HashType = 99
		}),
		createInvalidSBTest("invalid block size in superblock", "invalid block size", func(sb *Superblock) {
			sb.DataBlockSize = 1000
		}),
		createInvalidSBTest("salt too large in superblock", "salt too large", func(sb *Superblock) {
			sb.SaltSize = 300
		}),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, sb, offset := tt.setupTest()
			err := adoptParamsFromSuperblock(params, sb, offset)

			if tt.wantErr {
				if err == nil {
					t.Errorf("adoptParamsFromSuperblock() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("adoptParamsFromSuperblock() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("adoptParamsFromSuperblock() unexpected error = %v", err)
				return
			}

			if tt.verify != nil {
				tt.verify(t, params)
			}
		})
	}
}
