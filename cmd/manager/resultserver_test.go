/*
Copyright © 2019 Red Hat Inc.

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
package manager

import (
	"crypto/tls"
	"io"
	"os"
	"path"
	goruntime "runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func _readDirNames(path string) []string {
	f, err := os.Open(path)
	Expect(err).To(BeNil())
	list, err := f.Readdirnames(-1)
	f.Close()
	Expect(err).To(BeNil())
	return list
}

var _ = Describe("getServerTLSConfig", func() {
	It("returns secure defaults when not running in a cluster", func() {
		cfg := getServerTLSConfig()
		Expect(cfg).NotTo(BeNil())
		Expect(cfg.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
		Expect(cfg.NextProtos).To(ContainElement("http/1.1"))
	})
})

var _ = Describe("Resultserver testing", func() {
	Context("Raw result directory rotation", func() {
		var rootDir string
		var dir1, dir2, dir3, lostFoundDir string

		BeforeEach(func() {
			var err error
			rootDir, err = os.MkdirTemp("", "rotate-root")
			Expect(err).To(BeNil())

			// Ensure lost+found
			lostFoundDir = path.Join(rootDir, "lost+found")
			os.Mkdir(lostFoundDir, 0644)

			// Create temporary directories which represent what will be rotated
			dir1, err = os.MkdirTemp(rootDir, "rotate-1")
			Expect(err).To(BeNil())
			os.CreateTemp(dir1, "foo")
			fileToBeRead, err := os.CreateTemp(dir1, "bar")
			Expect(err).To(BeNil())
			os.CreateTemp(dir1, "baz")

			// Ensure next directory will have significant time difference
			time.Sleep(100 * time.Millisecond)
			dir2, err = os.MkdirTemp(rootDir, "rotate-2")
			Expect(err).To(BeNil())
			os.CreateTemp(dir2, "foo")
			os.CreateTemp(dir2, "bar")

			// Ensure next directory will have significant time difference
			time.Sleep(100 * time.Millisecond)
			dir3, err = os.MkdirTemp(rootDir, "rotate-3")
			Expect(err).To(BeNil())

			// chmod the dirs in reverse order to make sure we are really relying on
			// modification time and not change time (see OCPBUGSM-13482)
			time.Sleep(100 * time.Millisecond)
			err = os.Chmod(dir3, os.ModePerm)
			Expect(err).To(BeNil())
			time.Sleep(100 * time.Millisecond)
			err = os.Chmod(dir2, os.ModePerm)
			Expect(err).To(BeNil())
			time.Sleep(100 * time.Millisecond)
			err = os.Chmod(dir1, os.ModePerm)
			Expect(err).To(BeNil())

			// Read a file to ensure that hierarchy doesn't change
			_, err = io.ReadAll(fileToBeRead)
			Expect(err).To(BeNil())
		})

		AfterEach(func() {
			os.RemoveAll(rootDir)
		})

		It("Doesn't rotate directories if policy is disabled (3 directories with one lost+found and policy=0)", func() {
			err := rotateResultDirectories(rootDir, 0)
			Expect(err).To(BeNil())

			files := _readDirNames(rootDir)

			By("Verifying that the expected files are in the directory hierarchy")
			Expect(len(files)).To(Equal(4))
			Expect(path.Base(dir1)).To(BeElementOf(files))
			Expect(path.Base(dir2)).To(BeElementOf(files))
			Expect(path.Base(dir3)).To(BeElementOf(files))
			Expect(path.Base(lostFoundDir)).To(BeElementOf(files))

			By("Verifying that the expected files are indeed directories")
			Expect(dir1).To(BeADirectory())
			Expect(dir2).To(BeADirectory())
			Expect(dir3).To(BeADirectory())
			Expect(lostFoundDir).To(BeADirectory())
		})

		It("Doesn't rotate directories if they're within the rotation policy (3 directories with one lost+found and policy=4)", func() {
			err := rotateResultDirectories(rootDir, 4)
			Expect(err).To(BeNil())

			files := _readDirNames(rootDir)

			By("Verifying that the expected files are in the directory hierarchy")
			Expect(len(files)).To(Equal(4))
			Expect(path.Base(dir1)).To(BeElementOf(files))
			Expect(path.Base(dir2)).To(BeElementOf(files))
			Expect(path.Base(dir3)).To(BeElementOf(files))
			Expect(path.Base(lostFoundDir)).To(BeElementOf(files))

			By("Verifying that the expected files are indeed directories")
			Expect(dir1).To(BeADirectory())
			Expect(dir2).To(BeADirectory())
			Expect(dir3).To(BeADirectory())
			Expect(lostFoundDir).To(BeADirectory())
		})

		It("Doesn't rotate directories if they're within the rotation policy (3 directories with one lost+found and policy=3)", func() {
			err := rotateResultDirectories(rootDir, 3)
			Expect(err).To(BeNil())

			files := _readDirNames(rootDir)

			By("Verifying that the expected files are in the directory hierarchy")
			Expect(len(files)).To(Equal(4))
			Expect(path.Base(dir1)).To(BeElementOf(files))
			Expect(path.Base(dir2)).To(BeElementOf(files))
			Expect(path.Base(dir3)).To(BeElementOf(files))
			Expect(path.Base(lostFoundDir)).To(BeElementOf(files))

			By("Verifying that the expected files are indeed directories")
			Expect(dir1).To(BeADirectory())
			Expect(dir2).To(BeADirectory())
			Expect(dir3).To(BeADirectory())
			Expect(lostFoundDir).To(BeADirectory())
		})
		// If os arch is s390x skip following test, there is an issue on that platform
		// See https://github.com/ComplianceAsCode/compliance-operator/issues/534
		arch := goruntime.GOARCH
		if !strings.EqualFold(arch, "s390x") {
			It("Rotates directories according to the rotation policy (3 directories with one lost+found and policy=2)", func() {
				err := rotateResultDirectories(rootDir, 2)
				Expect(err).To(BeNil())

				files := _readDirNames(rootDir)

				By("Verifying that the expected files are in the directory hierarchy")
				Expect(len(files)).To(Equal(3))

				Expect(path.Base(dir1)).ToNot(BeElementOf(files))
				Expect(path.Base(dir2)).To(BeElementOf(files))
				Expect(path.Base(dir3)).To(BeElementOf(files))
				Expect(path.Base(lostFoundDir)).To(BeElementOf(files))

				By("Verifying that the expected files are indeed directories")
				Expect(dir3).To(BeADirectory())
				Expect(dir2).To(BeADirectory())
				Expect(lostFoundDir).To(BeADirectory())

			})
		}
	})
})
