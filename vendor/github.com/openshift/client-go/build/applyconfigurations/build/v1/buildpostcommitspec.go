// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

// BuildPostCommitSpecApplyConfiguration represents an declarative configuration of the BuildPostCommitSpec type for use
// with apply.
type BuildPostCommitSpecApplyConfiguration struct {
	Command []string `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	Script  *string  `json:"script,omitempty"`
}

// BuildPostCommitSpecApplyConfiguration constructs an declarative configuration of the BuildPostCommitSpec type for use with
// apply.
func BuildPostCommitSpec() *BuildPostCommitSpecApplyConfiguration {
	return &BuildPostCommitSpecApplyConfiguration{}
}

// WithCommand adds the given value to the Command field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Command field.
func (b *BuildPostCommitSpecApplyConfiguration) WithCommand(values ...string) *BuildPostCommitSpecApplyConfiguration {
	for i := range values {
		b.Command = append(b.Command, values[i])
	}
	return b
}

// WithArgs adds the given value to the Args field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Args field.
func (b *BuildPostCommitSpecApplyConfiguration) WithArgs(values ...string) *BuildPostCommitSpecApplyConfiguration {
	for i := range values {
		b.Args = append(b.Args, values[i])
	}
	return b
}

// WithScript sets the Script field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Script field is set to the value of the last call.
func (b *BuildPostCommitSpecApplyConfiguration) WithScript(value string) *BuildPostCommitSpecApplyConfiguration {
	b.Script = &value
	return b
}