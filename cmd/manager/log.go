/*
Copyright © 2020 Red Hat Inc.

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
	"fmt"
	"os"
)

var debugLog bool

func LOG(format string, a ...interface{}) {
	fmt.Printf(format+"\n", a...)
}

func DBG(format string, a ...interface{}) {
	if debugLog {
		LOG("debug: "+format, a...)
	}
}

func FATAL(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "FATAL:"+format+"\n", a...)
	os.Exit(1)
}
