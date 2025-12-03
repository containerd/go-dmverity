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

	verity "github.com/containerd/go-dmverity/pkg/verity"
)

func parseCloseArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("close", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return "", errors.New("require <name>")
	}
	return rest[0], nil
}

func runClose(name string) error {
	if err := verity.Close(name); err != nil {
		return err
	}

	fmt.Printf("/dev/mapper/%s removed\n", name)
	return nil
}
