/*
Copyright © 2024 Red Hat Inc.
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

package inputs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ComplianceAsCode/compliance-operator/pkg/celscanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNewFilesystemFetcher(t *testing.T) {
	tests := []struct {
		name     string
		basePath string
		expected string
	}{
		{
			name:     "empty base path",
			basePath: "",
			expected: "",
		},
		{
			name:     "with base path",
			basePath: "/etc",
			expected: "/etc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetcher := NewFilesystemFetcher(tt.basePath)
			assert.NotNil(t, fetcher)
			assert.Equal(t, tt.expected, fetcher.basePath)
		})
	}
}

func TestFilesystemFetcher_SupportsInputType(t *testing.T) {
	fetcher := NewFilesystemFetcher("")

	tests := []struct {
		name      string
		inputType celscanner.InputType
		expected  bool
	}{
		{
			name:      "supports file input",
			inputType: celscanner.InputTypeFile,
			expected:  true,
		},
		{
			name:      "does not support kubernetes input",
			inputType: celscanner.InputTypeKubernetes,
			expected:  false,
		},
		{
			name:      "does not support system input",
			inputType: celscanner.InputTypeSystem,
			expected:  false,
		},
		{
			name:      "does not support http input",
			inputType: celscanner.InputTypeHTTP,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fetcher.SupportsInputType(tt.inputType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFilesystemFetcher_FetchInputs_TextFile(t *testing.T) {
	// Create temporary test file
	tempDir, err := os.MkdirTemp("", "filesystem_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "Hello, World!"
	err = os.WriteFile(testFile, []byte(testContent), 0644)
	require.NoError(t, err)

	fetcher := NewFilesystemFetcher("")

	t.Run("text file without permissions", func(t *testing.T) {
		input := celscanner.NewFileInput("testfile", testFile, "text", false, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "testfile")
		assert.Equal(t, testContent, result["testfile"])
	})

	t.Run("text file with permissions", func(t *testing.T) {
		input := celscanner.NewFileInput("testfile", testFile, "text", false, true)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "testfile")

		fileData, ok := result["testfile"].(map[string]interface{})
		require.True(t, ok, "Expected map[string]interface{} for file with permissions")

		assert.Equal(t, testContent, fileData["content"])
		assert.Equal(t, "0644", fileData["perm"])
		assert.Contains(t, fileData["mode"].(string), "rw-r--r--")
		assert.NotEmpty(t, fileData["owner"])
		assert.NotEmpty(t, fileData["group"])
		assert.Equal(t, int64(len(testContent)), fileData["size"])
	})
}

func TestFilesystemFetcher_FetchInputs_JSONFile(t *testing.T) {
	// Create temporary test file
	tempDir, err := os.MkdirTemp("", "filesystem_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.json")
	testData := map[string]interface{}{
		"name":    "test",
		"version": "1.0",
		"enabled": true,
	}
	jsonContent, err := json.Marshal(testData)
	require.NoError(t, err)

	err = os.WriteFile(testFile, jsonContent, 0644)
	require.NoError(t, err)

	fetcher := NewFilesystemFetcher("")

	t.Run("json file without permissions", func(t *testing.T) {
		input := celscanner.NewFileInput("config", testFile, "json", false, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "config")

		parsedData, ok := result["config"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "test", parsedData["name"])
		assert.Equal(t, "1.0", parsedData["version"])
		assert.Equal(t, true, parsedData["enabled"])
	})

	t.Run("json file with permissions", func(t *testing.T) {
		input := celscanner.NewFileInput("config", testFile, "json", false, true)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "config")

		fileData, ok := result["config"].(map[string]interface{})
		require.True(t, ok)

		contentData, ok := fileData["content"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "test", contentData["name"])
		assert.Equal(t, "1.0", contentData["version"])
		assert.Equal(t, true, contentData["enabled"])

		assert.Equal(t, "0644", fileData["perm"])
		assert.NotEmpty(t, fileData["owner"])
		assert.NotEmpty(t, fileData["group"])
	})
}

func TestFilesystemFetcher_FetchInputs_YAMLFile(t *testing.T) {
	// Create temporary test file
	tempDir, err := os.MkdirTemp("", "filesystem_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.yaml")
	testData := map[string]interface{}{
		"server": map[string]interface{}{
			"port": 8080,
			"host": "localhost",
		},
		"database": map[string]interface{}{
			"url": "localhost:5432",
		},
	}
	yamlContent, err := yaml.Marshal(testData)
	require.NoError(t, err)

	err = os.WriteFile(testFile, yamlContent, 0644)
	require.NoError(t, err)

	fetcher := NewFilesystemFetcher("")

	t.Run("yaml file without permissions", func(t *testing.T) {
		input := celscanner.NewFileInput("config", testFile, "yaml", false, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "config")

		parsedData, ok := result["config"].(map[string]interface{})
		require.True(t, ok)

		server, ok := parsedData["server"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, 8080, server["port"])
		assert.Equal(t, "localhost", server["host"])
	})

	t.Run("yaml file with permissions", func(t *testing.T) {
		input := celscanner.NewFileInput("config", testFile, "yaml", false, true)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "config")

		fileData, ok := result["config"].(map[string]interface{})
		require.True(t, ok)

		contentData, ok := fileData["content"].(map[string]interface{})
		require.True(t, ok)

		server, ok := contentData["server"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, 8080, server["port"])
		assert.Equal(t, "localhost", server["host"])

		assert.Equal(t, "0644", fileData["perm"])
		assert.NotEmpty(t, fileData["owner"])
		assert.NotEmpty(t, fileData["group"])
	})
}

func TestFilesystemFetcher_FetchInputs_Directory(t *testing.T) {
	// Create temporary test directory with files
	tempDir, err := os.MkdirTemp("", "filesystem_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create test files
	file1 := filepath.Join(tempDir, "file1.txt")
	file2 := filepath.Join(tempDir, "file2.txt")
	file3 := filepath.Join(tempDir, "config.json")

	err = os.WriteFile(file1, []byte("content1"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(file2, []byte("content2"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(file3, []byte(`{"key": "value"}`), 0644)
	require.NoError(t, err)

	// Create subdirectory
	subDir := filepath.Join(tempDir, "subdir")
	err = os.Mkdir(subDir, 0755)
	require.NoError(t, err)

	subFile := filepath.Join(subDir, "subfile.txt")
	err = os.WriteFile(subFile, []byte("subcontent"), 0644)
	require.NoError(t, err)

	fetcher := NewFilesystemFetcher("")

	t.Run("directory without recursion", func(t *testing.T) {
		input := celscanner.NewFileInput("files", tempDir, "text", false, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "files")

		files, ok := result["files"].(map[string]interface{})
		require.True(t, ok)

		assert.Contains(t, files, "file1.txt")
		assert.Contains(t, files, "file2.txt")
		assert.Equal(t, "content1", files["file1.txt"])
		assert.Equal(t, "content2", files["file2.txt"])

		// Should not contain subdirectory files
		assert.NotContains(t, files, "subdir/subfile.txt")
	})

	t.Run("directory with recursion", func(t *testing.T) {
		input := celscanner.NewFileInput("files", tempDir, "text", true, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "files")

		files, ok := result["files"].(map[string]interface{})
		require.True(t, ok)

		assert.Contains(t, files, "file1.txt")
		assert.Contains(t, files, "file2.txt")
		assert.Contains(t, files, "subdir/subfile.txt")
		assert.Equal(t, "subcontent", files["subdir/subfile.txt"])
	})

	t.Run("directory with permissions", func(t *testing.T) {
		input := celscanner.NewFileInput("files", tempDir, "text", false, true)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "files")

		files, ok := result["files"].(map[string]interface{})
		require.True(t, ok)

		file1Data, ok := files["file1.txt"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "content1", file1Data["content"])
		assert.Equal(t, "0644", file1Data["perm"])
		assert.NotEmpty(t, file1Data["owner"])
		assert.NotEmpty(t, file1Data["group"])
	})
}

func TestFilesystemFetcher_FetchInputs_FormatFiltering(t *testing.T) {
	// Create temporary test directory with different file types
	tempDir, err := os.MkdirTemp("", "filesystem_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create test files with different extensions
	jsonFile := filepath.Join(tempDir, "config.json")
	yamlFile := filepath.Join(tempDir, "config.yaml")
	txtFile := filepath.Join(tempDir, "readme.txt")

	err = os.WriteFile(jsonFile, []byte(`{"type": "json"}`), 0644)
	require.NoError(t, err)
	err = os.WriteFile(yamlFile, []byte("type: yaml"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(txtFile, []byte("type: text"), 0644)
	require.NoError(t, err)

	fetcher := NewFilesystemFetcher("")

	t.Run("json format filtering", func(t *testing.T) {
		input := celscanner.NewFileInput("configs", tempDir, "json", false, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "configs")

		configs, ok := result["configs"].(map[string]interface{})
		require.True(t, ok)

		assert.Contains(t, configs, "config.json")
		assert.NotContains(t, configs, "config.yaml")
		assert.NotContains(t, configs, "readme.txt")
	})

	t.Run("yaml format filtering", func(t *testing.T) {
		input := celscanner.NewFileInput("configs", tempDir, "yaml", false, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "configs")

		configs, ok := result["configs"].(map[string]interface{})
		require.True(t, ok)

		assert.Contains(t, configs, "config.yaml")
		assert.NotContains(t, configs, "config.json")
		assert.NotContains(t, configs, "readme.txt")
	})

	t.Run("text format includes all", func(t *testing.T) {
		input := celscanner.NewFileInput("configs", tempDir, "text", false, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "configs")

		configs, ok := result["configs"].(map[string]interface{})
		require.True(t, ok)

		assert.Contains(t, configs, "config.json")
		assert.Contains(t, configs, "config.yaml")
		assert.Contains(t, configs, "readme.txt")
	})
}

func TestFilesystemFetcher_FetchInputs_BasePath(t *testing.T) {
	// Create temporary test directory
	tempDir, err := os.MkdirTemp("", "filesystem_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	fetcher := NewFilesystemFetcher(tempDir)

	t.Run("relative path with base path", func(t *testing.T) {
		input := celscanner.NewFileInput("testfile", "test.txt", "text", false, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "testfile")
		assert.Equal(t, "test content", result["testfile"])
	})

	t.Run("absolute path ignores base path", func(t *testing.T) {
		input := celscanner.NewFileInput("testfile", testFile, "text", false, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "testfile")
		assert.Equal(t, "test content", result["testfile"])
	})
}

func TestFilesystemFetcher_FetchInputs_Errors(t *testing.T) {
	fetcher := NewFilesystemFetcher("")

	t.Run("nonexistent file", func(t *testing.T) {
		input := celscanner.NewFileInput("missing", "/nonexistent/file.txt", "text", false, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to stat path")
	})

	t.Run("invalid json", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "filesystem_test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		testFile := filepath.Join(tempDir, "invalid.json")
		err = os.WriteFile(testFile, []byte("invalid json content"), 0644)
		require.NoError(t, err)

		input := celscanner.NewFileInput("invalid", testFile, "json", false, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to parse JSON")
	})

	t.Run("invalid yaml", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "filesystem_test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		testFile := filepath.Join(tempDir, "invalid.yaml")
		err = os.WriteFile(testFile, []byte("invalid: yaml: content: ["), 0644)
		require.NoError(t, err)

		input := celscanner.NewFileInput("invalid", testFile, "yaml", false, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to parse YAML")
	})

	t.Run("wrong input type", func(t *testing.T) {
		input := celscanner.NewKubernetesInput("pods", "", "v1", "pods", "", "")
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("invalid input spec", func(t *testing.T) {
		// Create a mock input with invalid spec
		mockInput := &celscanner.SimpleInput{
			InputName: "test",
			InputType: celscanner.InputTypeFile,
			InputSpec: &celscanner.SimpleKubernetesInputSpec{}, // Wrong spec type
		}

		result, err := fetcher.FetchInputs([]celscanner.Input{mockInput}, nil)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "invalid file input spec")
	})
}

func TestFilesystemFetcher_FetchInputs_SpecialPermissions(t *testing.T) {
	// Create temporary test file with special permissions
	tempDir, err := os.MkdirTemp("", "filesystem_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "restricted.txt")
	err = os.WriteFile(testFile, []byte("secret content"), 0600)
	require.NoError(t, err)

	fetcher := NewFilesystemFetcher("")

	t.Run("restricted file permissions", func(t *testing.T) {
		input := celscanner.NewFileInput("restricted", testFile, "text", false, true)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "restricted")

		fileData, ok := result["restricted"].(map[string]interface{})
		require.True(t, ok)

		assert.Equal(t, "secret content", fileData["content"])
		assert.Equal(t, "0600", fileData["perm"])
		assert.Contains(t, fileData["mode"].(string), "rw-------")
	})

	// Test with executable file
	execFile := filepath.Join(tempDir, "script.sh")
	err = os.WriteFile(execFile, []byte("#!/bin/bash\necho hello"), 0755)
	require.NoError(t, err)

	t.Run("executable file permissions", func(t *testing.T) {
		input := celscanner.NewFileInput("script", execFile, "text", false, true)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Contains(t, result, "script")

		fileData, ok := result["script"].(map[string]interface{})
		require.True(t, ok)

		assert.Equal(t, "0755", fileData["perm"])
		assert.Contains(t, fileData["mode"].(string), "rwxr-xr-x")
	})
}

func TestFilesystemFetcher_GetFileMetadata(t *testing.T) {
	// Create temporary test file
	tempDir, err := os.MkdirTemp("", "filesystem_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "Hello, World!"
	err = os.WriteFile(testFile, []byte(testContent), 0644)
	require.NoError(t, err)

	fetcher := NewFilesystemFetcher("")

	t.Run("get file metadata", func(t *testing.T) {
		mode, perm, owner, group, size := fetcher.getFileMetadata(testFile)

		assert.Contains(t, mode, "rw-r--r--")
		assert.Equal(t, "0644", perm)
		assert.NotEmpty(t, owner)
		assert.NotEmpty(t, group)
		assert.Equal(t, int64(len(testContent)), size)
	})

	t.Run("nonexistent file", func(t *testing.T) {
		mode, perm, owner, group, size := fetcher.getFileMetadata("/nonexistent/file.txt")

		assert.Empty(t, mode)
		assert.Empty(t, perm)
		assert.Empty(t, owner)
		assert.Empty(t, group)
		assert.Equal(t, int64(0), size)
	})
}

func TestFilesystemFetcher_ParseFileContent(t *testing.T) {
	fetcher := NewFilesystemFetcher("")

	t.Run("parse json", func(t *testing.T) {
		jsonContent := `{"name": "test", "value": 42}`
		result, err := fetcher.parseFileContent([]byte(jsonContent), "json", "test.json")

		require.NoError(t, err)
		data, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "test", data["name"])
		assert.Equal(t, float64(42), data["value"])
	})

	t.Run("parse yaml", func(t *testing.T) {
		yamlContent := "name: test\nvalue: 42"
		result, err := fetcher.parseFileContent([]byte(yamlContent), "yaml", "test.yaml")

		require.NoError(t, err)
		data, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "test", data["name"])
		assert.Equal(t, 42, data["value"])
	})

	t.Run("parse text", func(t *testing.T) {
		textContent := "Hello, World!"
		result, err := fetcher.parseFileContent([]byte(textContent), "text", "test.txt")

		require.NoError(t, err)
		assert.Equal(t, textContent, result)
	})

	t.Run("infer format from extension", func(t *testing.T) {
		jsonContent := `{"inferred": true}`
		result, err := fetcher.parseFileContent([]byte(jsonContent), "", "test.json")

		require.NoError(t, err)
		data, ok := result.(map[string]interface{})
		require.True(t, ok, "Expected map[string]interface{} but got %T", result)
		assert.Equal(t, true, data["inferred"])
	})

	t.Run("unknown format defaults to text", func(t *testing.T) {
		content := "unknown format content"
		result, err := fetcher.parseFileContent([]byte(content), "unknown", "test.unknown")

		require.NoError(t, err)
		assert.Equal(t, content, result)
	})
}

func TestFilesystemFetcher_MatchesFormat(t *testing.T) {
	fetcher := NewFilesystemFetcher("")

	tests := []struct {
		name     string
		filePath string
		format   string
		expected bool
	}{
		{
			name:     "json file with json format",
			filePath: "test.json",
			format:   "json",
			expected: true,
		},
		{
			name:     "yaml file with yaml format",
			filePath: "test.yaml",
			format:   "yaml",
			expected: true,
		},
		{
			name:     "yml file with yaml format",
			filePath: "test.yml",
			format:   "yaml",
			expected: true,
		},
		{
			name:     "txt file with text format",
			filePath: "test.txt",
			format:   "text",
			expected: true,
		},
		{
			name:     "any file with empty format",
			filePath: "test.anything",
			format:   "",
			expected: true,
		},
		{
			name:     "json file with yaml format",
			filePath: "test.json",
			format:   "yaml",
			expected: false,
		},
		{
			name:     "yaml file with json format",
			filePath: "test.yaml",
			format:   "json",
			expected: false,
		},
		{
			name:     "unknown format accepts all",
			filePath: "test.anything",
			format:   "unknown",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fetcher.matchesFormat(tt.filePath, tt.format)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHelperFunctions(t *testing.T) {
	// Create temporary test directory and file
	tempDir, err := os.MkdirTemp("", "filesystem_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "Hello, World!"
	err = os.WriteFile(testFile, []byte(testContent), 0644)
	require.NoError(t, err)

	subDir := filepath.Join(tempDir, "subdir")
	err = os.Mkdir(subDir, 0755)
	require.NoError(t, err)

	t.Run("FileExists", func(t *testing.T) {
		assert.True(t, FileExists(testFile))
		assert.True(t, FileExists(tempDir))
		assert.False(t, FileExists("/nonexistent/file.txt"))
	})

	t.Run("IsDirectory", func(t *testing.T) {
		assert.True(t, IsDirectory(tempDir))
		assert.True(t, IsDirectory(subDir))
		assert.False(t, IsDirectory(testFile))
		assert.False(t, IsDirectory("/nonexistent/path"))
	})

	t.Run("GetFileInfo", func(t *testing.T) {
		info, err := GetFileInfo(testFile)
		require.NoError(t, err)
		assert.Equal(t, "test.txt", info.Name())
		assert.Equal(t, int64(len(testContent)), info.Size())
		assert.False(t, info.IsDir())

		info, err = GetFileInfo(tempDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())

		_, err = GetFileInfo("/nonexistent/file.txt")
		assert.Error(t, err)
	})

	t.Run("ReadFileAsString", func(t *testing.T) {
		content, err := ReadFileAsString(testFile)
		require.NoError(t, err)
		assert.Equal(t, testContent, content)

		_, err = ReadFileAsString("/nonexistent/file.txt")
		assert.Error(t, err)
	})

	t.Run("ListFiles", func(t *testing.T) {
		files, err := ListFiles(tempDir)
		require.NoError(t, err)
		assert.Contains(t, files, "test.txt")
		assert.NotContains(t, files, "subdir") // Should not include directories

		_, err = ListFiles("/nonexistent/dir")
		assert.Error(t, err)
	})

	t.Run("ListDirectories", func(t *testing.T) {
		dirs, err := ListDirectories(tempDir)
		require.NoError(t, err)
		assert.Contains(t, dirs, "subdir")
		assert.NotContains(t, dirs, "test.txt") // Should not include files

		_, err = ListDirectories("/nonexistent/dir")
		assert.Error(t, err)
	})
}

func TestValidateFileInputSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    celscanner.FileInputSpec
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid spec",
			spec: &celscanner.SimpleFileInputSpec{
				FilePath:    "/etc/config.yaml",
				FileFormat:  "yaml",
				IsRecursive: false,
				CheckPerms:  false,
			},
			wantErr: false,
		},
		{
			name: "empty path",
			spec: &celscanner.SimpleFileInputSpec{
				FilePath:    "",
				FileFormat:  "yaml",
				IsRecursive: false,
				CheckPerms:  false,
			},
			wantErr: true,
			errMsg:  "path is required",
		},
		{
			name: "invalid format",
			spec: &celscanner.SimpleFileInputSpec{
				FilePath:    "/etc/config.yaml",
				FileFormat:  "invalid",
				IsRecursive: false,
				CheckPerms:  false,
			},
			wantErr: true,
			errMsg:  "unsupported format",
		},
		{
			name: "valid json format",
			spec: &celscanner.SimpleFileInputSpec{
				FilePath:    "/etc/config.json",
				FileFormat:  "json",
				IsRecursive: false,
				CheckPerms:  false,
			},
			wantErr: false,
		},
		{
			name: "valid yml format",
			spec: &celscanner.SimpleFileInputSpec{
				FilePath:    "/etc/config.yml",
				FileFormat:  "yml",
				IsRecursive: false,
				CheckPerms:  false,
			},
			wantErr: false,
		},
		{
			name: "valid text format",
			spec: &celscanner.SimpleFileInputSpec{
				FilePath:    "/etc/config.txt",
				FileFormat:  "text",
				IsRecursive: false,
				CheckPerms:  false,
			},
			wantErr: false,
		},
		{
			name: "empty format is valid",
			spec: &celscanner.SimpleFileInputSpec{
				FilePath:    "/etc/config",
				FileFormat:  "",
				IsRecursive: false,
				CheckPerms:  false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFileInputSpec(tt.spec)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFilesystemFetcher_Integration(t *testing.T) {
	// Create a complex test directory structure
	tempDir, err := os.MkdirTemp("", "filesystem_integration_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create config files
	configDir := filepath.Join(tempDir, "config")
	err = os.Mkdir(configDir, 0755)
	require.NoError(t, err)

	appConfig := filepath.Join(configDir, "app.yaml")
	err = os.WriteFile(appConfig, []byte("name: myapp\nversion: 1.0\nport: 8080"), 0644)
	require.NoError(t, err)

	dbConfig := filepath.Join(configDir, "database.json")
	err = os.WriteFile(dbConfig, []byte(`{"host": "localhost", "port": 5432, "name": "mydb"}`), 0600)
	require.NoError(t, err)

	// Create logs directory
	logsDir := filepath.Join(tempDir, "logs")
	err = os.Mkdir(logsDir, 0755)
	require.NoError(t, err)

	logFile := filepath.Join(logsDir, "app.log")
	err = os.WriteFile(logFile, []byte("2024-01-01 INFO: Application started"), 0644)
	require.NoError(t, err)

	fetcher := NewFilesystemFetcher("")

	t.Run("complex directory structure with permissions", func(t *testing.T) {
		// Test multiple inputs with different configurations
		inputs := []celscanner.Input{
			celscanner.NewFileInput("app_config", appConfig, "yaml", false, true),
			celscanner.NewFileInput("db_config", dbConfig, "json", false, true),
			celscanner.NewFileInput("all_configs", configDir, "yaml", false, true),
			celscanner.NewFileInput("logs", logsDir, "text", false, false),
		}

		result, err := fetcher.FetchInputs(inputs, nil)
		require.NoError(t, err)

		// Check app config
		appData, ok := result["app_config"].(map[string]interface{})
		require.True(t, ok)
		appContent, ok := appData["content"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "myapp", appContent["name"])
		assert.Equal(t, "0644", appData["perm"])

		// Check db config
		dbData, ok := result["db_config"].(map[string]interface{})
		require.True(t, ok)
		dbContent, ok := dbData["content"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "localhost", dbContent["host"])
		assert.Equal(t, "0600", dbData["perm"]) // Restrictive permissions

		// Check all configs (directory)
		allConfigs, ok := result["all_configs"].(map[string]interface{})
		require.True(t, ok)
		assert.Contains(t, allConfigs, "app.yaml")

		// Check logs (no permissions)
		logs, ok := result["logs"].(map[string]interface{})
		require.True(t, ok)
		assert.Contains(t, logs, "app.log")
		assert.Equal(t, "2024-01-01 INFO: Application started", logs["app.log"])
	})
}

// Benchmark tests
func BenchmarkFilesystemFetcher_FetchTextFile(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "filesystem_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("benchmark content"), 0644)
	require.NoError(b, err)

	fetcher := NewFilesystemFetcher("")
	input := celscanner.NewFileInput("test", testFile, "text", false, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)
		require.NoError(b, err)
	}
}

func BenchmarkFilesystemFetcher_FetchWithPermissions(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "filesystem_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("benchmark content"), 0644)
	require.NoError(b, err)

	fetcher := NewFilesystemFetcher("")
	input := celscanner.NewFileInput("test", testFile, "text", false, true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)
		require.NoError(b, err)
	}
}

func BenchmarkFilesystemFetcher_FetchDirectory(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "filesystem_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	// Create multiple files
	for i := 0; i < 10; i++ {
		testFile := filepath.Join(tempDir, "file"+strconv.Itoa(i)+".txt")
		err = os.WriteFile(testFile, []byte("content "+strconv.Itoa(i)), 0644)
		require.NoError(b, err)
	}

	fetcher := NewFilesystemFetcher("")
	input := celscanner.NewFileInput("files", tempDir, "text", false, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)
		require.NoError(b, err)
	}
}
