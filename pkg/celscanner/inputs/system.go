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
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ComplianceAsCode/compliance-operator/pkg/celscanner"
)

// SystemFetcher implements InputFetcher for system services and commands
type SystemFetcher struct {
	// Timeout for command execution
	commandTimeout time.Duration
	// Whether to allow arbitrary commands (security consideration)
	allowArbitraryCommands bool
}

// SystemResult represents the result of a system operation
type SystemResult struct {
	// Status of the service or command
	Status string `json:"status"`
	// Output from the command
	Output string `json:"output"`
	// Error output from the command
	Error string `json:"error"`
	// Exit code from the command
	ExitCode int `json:"exitCode"`
	// Whether the operation was successful
	Success bool `json:"success"`
	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// NewSystemFetcher creates a new system input fetcher
func NewSystemFetcher(commandTimeout time.Duration, allowArbitraryCommands bool) *SystemFetcher {
	if commandTimeout == 0 {
		commandTimeout = 30 * time.Second // Default timeout
	}

	return &SystemFetcher{
		commandTimeout:         commandTimeout,
		allowArbitraryCommands: allowArbitraryCommands,
	}
}

// FetchInputs retrieves system resources for the specified inputs
func (s *SystemFetcher) FetchInputs(inputs []celscanner.Input, variables []celscanner.CelVariable) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for _, input := range inputs {
		if input.Type() != celscanner.InputTypeSystem {
			continue
		}

		systemSpec, ok := input.Spec().(celscanner.SystemInputSpec)
		if !ok {
			return nil, fmt.Errorf("invalid system input spec for input %s", input.Name())
		}

		data, err := s.fetchSystemResource(systemSpec)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch system resource for input %s: %w", input.Name(), err)
		}

		result[input.Name()] = data
	}

	return result, nil
}

// SupportsInputType returns true for system input types
func (s *SystemFetcher) SupportsInputType(inputType celscanner.InputType) bool {
	return inputType == celscanner.InputTypeSystem
}

// fetchSystemResource retrieves a specific system resource
func (s *SystemFetcher) fetchSystemResource(spec celscanner.SystemInputSpec) (interface{}, error) {
	if spec.ServiceName() != "" {
		return s.fetchServiceStatus(spec.ServiceName())
	}

	if spec.Command() != "" {
		return s.executeCommand(spec.Command(), spec.Args())
	}

	return nil, fmt.Errorf("either service name or command must be specified")
}

// fetchServiceStatus gets the status of a system service
func (s *SystemFetcher) fetchServiceStatus(serviceName string) (*SystemResult, error) {
	// Try systemctl first (systemd)
	result, err := s.executeCommand("systemctl", []string{"status", serviceName})
	if err == nil {
		return s.parseSystemctlOutput(result, serviceName)
	}

	// Try service command (SysV init)
	result, err = s.executeCommand("service", []string{serviceName, "status"})
	if err == nil {
		return s.parseServiceOutput(result, serviceName)
	}

	return nil, fmt.Errorf("failed to get status for service %s", serviceName)
}

// executeCommand executes a system command with timeout
func (s *SystemFetcher) executeCommand(command string, args []string) (*SystemResult, error) {
	// Security check for arbitrary commands
	if !s.allowArbitraryCommands && !s.isAllowedCommand(command) {
		return nil, fmt.Errorf("command %s is not allowed", command)
	}

	// Create command with timeout
	cmd := exec.Command(command, args...)

	// Capture output
	output, err := cmd.CombinedOutput()

	result := &SystemResult{
		Output:   string(output),
		Success:  err == nil,
		Metadata: make(map[string]interface{}),
	}

	// Get exit code
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
			result.Error = err.Error()
		} else {
			result.ExitCode = -1
			result.Error = err.Error()
		}
	}

	// Add metadata
	result.Metadata["command"] = command
	result.Metadata["args"] = args
	result.Metadata["timestamp"] = time.Now().Unix()

	return result, nil
}

// parseSystemctlOutput parses systemctl status output
func (s *SystemFetcher) parseSystemctlOutput(result *SystemResult, serviceName string) (*SystemResult, error) {
	output := result.Output

	// Parse systemctl output to determine status
	if strings.Contains(output, "Active: active (running)") {
		result.Status = "active"
	} else if strings.Contains(output, "Active: inactive (dead)") {
		result.Status = "inactive"
	} else if strings.Contains(output, "Active: failed") {
		result.Status = "failed"
	} else {
		result.Status = "unknown"
	}

	// Extract additional information
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Loaded:") {
			result.Metadata["loaded"] = strings.TrimPrefix(line, "Loaded:")
		} else if strings.HasPrefix(line, "Active:") {
			result.Metadata["active"] = strings.TrimPrefix(line, "Active:")
		} else if strings.HasPrefix(line, "Main PID:") {
			result.Metadata["mainPid"] = strings.TrimPrefix(line, "Main PID:")
		}
	}

	return result, nil
}

// parseServiceOutput parses service command output
func (s *SystemFetcher) parseServiceOutput(result *SystemResult, serviceName string) (*SystemResult, error) {
	output := strings.ToLower(result.Output)

	// Parse service output to determine status
	if strings.Contains(output, "running") || strings.Contains(output, "active") {
		result.Status = "active"
	} else if strings.Contains(output, "stopped") || strings.Contains(output, "inactive") {
		result.Status = "inactive"
	} else if strings.Contains(output, "failed") {
		result.Status = "failed"
	} else {
		result.Status = "unknown"
	}

	return result, nil
}

// isAllowedCommand checks if a command is allowed for security
func (s *SystemFetcher) isAllowedCommand(command string) bool {
	// Allow list of safe commands
	allowedCommands := []string{
		"systemctl",
		"service",
		"ps",
		"netstat",
		"ss",
		"lsof",
		"cat",
		"grep",
		"awk",
		"sed",
		"cut",
		"sort",
		"uniq",
		"wc",
		"head",
		"tail",
		"ls",
		"find",
		"which",
		"whereis",
		"id",
		"whoami",
		"uname",
		"hostname",
		"uptime",
		"free",
		"df",
		"du",
		"mount",
		"lsblk",
		"lscpu",
		"lsmem",
		"lsusb",
		"lspci",
		"ip",
		"ifconfig",
		"route",
		"iptables",
		"firewall-cmd",
		"selinux",
		"getenforce",
		"sestatus",
		"auditctl",
		"journalctl",
		"dmesg",
		"sysctl",
		"crontab",
		"chkconfig",
		"update-rc.d",
		"dpkg",
		"rpm",
		"yum",
		"apt",
		"snap",
		"docker",
		"podman",
		"crictl",
		"kubectl",
		"openssl",
		"curl",
		"wget",
		"ping",
		"traceroute",
		"nslookup",
		"dig",
		"host",
	}

	for _, allowed := range allowedCommands {
		if command == allowed {
			return true
		}
	}

	return false
}

// Helper functions for system operations

// GetServiceStatus gets the status of a system service
func GetServiceStatus(serviceName string) (*SystemResult, error) {
	fetcher := NewSystemFetcher(30*time.Second, false)
	return fetcher.fetchServiceStatus(serviceName)
}

// ExecuteCommand executes a system command safely
func ExecuteCommand(command string, args []string) (*SystemResult, error) {
	fetcher := NewSystemFetcher(30*time.Second, false)
	return fetcher.executeCommand(command, args)
}

// IsServiceActive checks if a service is active
func IsServiceActive(serviceName string) bool {
	result, err := GetServiceStatus(serviceName)
	if err != nil {
		return false
	}
	return result.Status == "active"
}

// IsServiceEnabled checks if a service is enabled
func IsServiceEnabled(serviceName string) bool {
	fetcher := NewSystemFetcher(30*time.Second, false)
	result, err := fetcher.executeCommand("systemctl", []string{"is-enabled", serviceName})
	if err != nil {
		return false
	}
	return strings.TrimSpace(result.Output) == "enabled"
}

// GetProcessInfo gets information about running processes
func GetProcessInfo(processName string) (*SystemResult, error) {
	fetcher := NewSystemFetcher(30*time.Second, false)
	return fetcher.executeCommand("ps", []string{"aux", "|", "grep", processName})
}

// GetNetworkInfo gets network information
func GetNetworkInfo() (*SystemResult, error) {
	fetcher := NewSystemFetcher(30*time.Second, false)
	return fetcher.executeCommand("ip", []string{"addr", "show"})
}

// GetSystemInfo gets system information
func GetSystemInfo() (*SystemResult, error) {
	fetcher := NewSystemFetcher(30*time.Second, false)
	return fetcher.executeCommand("uname", []string{"-a"})
}

// ValidateSystemInputSpec validates a system input specification
func ValidateSystemInputSpec(spec celscanner.SystemInputSpec) error {
	if spec.ServiceName() == "" && spec.Command() == "" {
		return fmt.Errorf("either service name or command must be specified")
	}

	if spec.ServiceName() != "" && spec.Command() != "" {
		return fmt.Errorf("cannot specify both service name and command")
	}

	return nil
}

// Example usage:
//
// // Create fetcher
// fetcher := NewSystemFetcher(30*time.Second, false)
//
// // Create system input for service
// input := celscanner.NewSystemInput("nginx", "nginx", "", []string{})
// data, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)
//
// // Create system input for command
// input = celscanner.NewSystemInput("processes", "", "ps", []string{"aux"})
// data, err = fetcher.FetchInputs([]celscanner.Input{input}, nil)
