/*
Copyright © 2025 Red Hat Inc.
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

package fetchers

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ComplianceAsCode/compliance-sdk/pkg/scanner"
	"gopkg.in/yaml.v3"
)

// FilesystemFetcher implements InputFetcher for file system resources
type FilesystemFetcher struct {
	// Optional base path for relative file paths
	basePath string
}

// NewFilesystemFetcher creates a new filesystem input fetcher
func NewFilesystemFetcher(basePath string) *FilesystemFetcher {
	return &FilesystemFetcher{
		basePath: basePath,
	}
}

// FetchInputs retrieves file system resources for the specified inputs
func (f *FilesystemFetcher) FetchInputs(inputs []scanner.Input, variables []scanner.CelVariable) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for _, input := range inputs {
		if input.Type() != scanner.InputTypeFile {
			continue
		}

		fileSpec, ok := input.Spec().(scanner.FileInputSpec)
		if !ok {
			return nil, fmt.Errorf("invalid file input spec for input %s", input.Name())
		}

		data, err := f.fetchFileResource(fileSpec)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch file resource for input %s: %w", input.Name(), err)
		}

		result[input.Name()] = data
	}

	return result, nil
}

// SupportsInputType returns true for file input types
func (f *FilesystemFetcher) SupportsInputType(inputType scanner.InputType) bool {
	return inputType == scanner.InputTypeFile
}

// fetchFileResource retrieves a specific file system resource
func (f *FilesystemFetcher) fetchFileResource(spec scanner.FileInputSpec) (interface{}, error) {
	path := spec.Path()

	// Make path absolute if it's relative and we have a base path
	if f.basePath != "" && !filepath.IsAbs(path) {
		path = filepath.Join(f.basePath, path)
	}

	// Check if path exists
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path %s: %w", path, err)
	}

	if info.IsDir() {
		return f.fetchDirectory(path, spec)
	}

	return f.fetchFile(path, spec)
}

// fetchFile reads and parses a single file
func (f *FilesystemFetcher) fetchFile(path string, spec scanner.FileInputSpec) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	parsed, err := f.parseFileContent(data, spec.Format(), path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file %s: %w", path, err)
	}

	if !spec.CheckPermissions() {
		return parsed, nil
	}

	mode, perm, owner, group, size := f.getFileMetadata(path)

	return map[string]interface{}{
		"content": parsed,
		"mode":    mode,
		"perm":    perm,
		"owner":   owner,
		"group":   group,
		"size":    size,
	}, nil
}

// getFileMetadata retrieves file metadata including permissions, ownership, and group
func (f *FilesystemFetcher) getFileMetadata(path string) (mode, perm, owner, group string, size int64) {
	info, err := os.Stat(path)
	if err != nil {
		return "", "", "", "", 0
	}

	size = info.Size()
	mode = info.Mode().String()
	perm = fmt.Sprintf("%04o", info.Mode().Perm())

	// Get owner and group information
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		// Get owner username
		if u, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10)); err == nil {
			owner = u.Username
		} else {
			owner = strconv.FormatUint(uint64(stat.Uid), 10)
		}

		// Get group name
		if g, err := user.LookupGroupId(strconv.FormatUint(uint64(stat.Gid), 10)); err == nil {
			group = g.Name
		} else {
			group = strconv.FormatUint(uint64(stat.Gid), 10)
		}
	}

	return mode, perm, owner, group, size
}

// fetchDirectory reads files from a directory
func (f *FilesystemFetcher) fetchDirectory(path string, spec scanner.FileInputSpec) (interface{}, error) {
	result := make(map[string]interface{})

	walkFunc := func(filePath string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			// Skip subdirectories if not recursive
			if !spec.Recursive() && filePath != path {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip files that don't match the expected format
		if !f.matchesFormat(filePath, spec.Format()) {
			return nil
		}

		// Read and parse file
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", filePath, err)
		}

		parsed, err := f.parseFileContent(content, spec.Format(), filePath)
		if err != nil {
			return fmt.Errorf("failed to parse file %s: %w", filePath, err)
		}

		// Use relative path as key
		relPath, err := filepath.Rel(path, filePath)
		if err != nil {
			relPath = filePath
		}

		if !spec.CheckPermissions() {
			result[relPath] = parsed
			return nil
		}

		mode, perm, owner, group, size := f.getFileMetadata(filePath)

		result[relPath] = map[string]interface{}{
			"content": parsed,
			"mode":    mode,
			"perm":    perm,
			"owner":   owner,
			"group":   group,
			"size":    size,
		}
		return nil
	}

	err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		return walkFunc(filePath, info, nil)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", path, err)
	}

	return result, nil
}

// parseFileContent parses file content based on format
func (f *FilesystemFetcher) parseFileContent(content []byte, format string, filePath string) (interface{}, error) {
	switch strings.ToLower(format) {
	case "json":
		return f.parseJSON(content)
	case "yaml", "yml":
		return f.parseYAML(content)
	case "text", "txt":
		return string(content), nil
	case "":
		// Try to infer format from file extension
		ext := strings.ToLower(filepath.Ext(filePath))
		switch ext {
		case ".json":
			return f.parseJSON(content)
		case ".yaml", ".yml":
			return f.parseYAML(content)
		default:
			return string(content), nil
		}
	default:
		// Try to infer format from file extension for unknown formats
		ext := strings.ToLower(filepath.Ext(filePath))
		switch ext {
		case ".json":
			return f.parseJSON(content)
		case ".yaml", ".yml":
			return f.parseYAML(content)
		default:
			return string(content), nil
		}
	}
}

// parseJSON parses JSON content
func (f *FilesystemFetcher) parseJSON(content []byte) (interface{}, error) {
	var result interface{}
	if err := json.Unmarshal(content, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return result, nil
}

// parseYAML parses YAML content
func (f *FilesystemFetcher) parseYAML(content []byte) (interface{}, error) {
	var result interface{}
	if err := yaml.Unmarshal(content, &result); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	return result, nil
}

// matchesFormat checks if file matches the expected format
func (f *FilesystemFetcher) matchesFormat(filePath string, format string) bool {
	if format == "" || format == "text" || format == "txt" {
		return true // Accept any file for text format
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	switch strings.ToLower(format) {
	case "json":
		return ext == ".json"
	case "yaml", "yml":
		return ext == ".yaml" || ext == ".yml"
	default:
		return true // Accept any file if format is unknown
	}
}

// Helper functions for file operations

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsDirectory checks if a path is a directory
func IsDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// GetFileInfo returns file information
func GetFileInfo(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

// ReadFileAsString reads a file as a string
func ReadFileAsString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ListFiles lists files in a directory (non-recursively)
func ListFiles(dirPath string) ([]string, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}

	return files, nil
}

// ListDirectories lists directories in a directory
func ListDirectories(dirPath string) ([]string, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry.Name())
		}
	}

	return dirs, nil
}

// ValidateFileInputSpec validates a file input specification
func ValidateFileInputSpec(spec scanner.FileInputSpec) error {
	if spec.Path() == "" {
		return fmt.Errorf("path is required")
	}

	// Validate format if specified
	format := strings.ToLower(spec.Format())
	if format != "" {
		validFormats := []string{"json", "yaml", "yml", "text", "txt"}
		valid := false
		for _, validFormat := range validFormats {
			if format == validFormat {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("unsupported format: %s", format)
		}
	}

	return nil
}
