package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ComplianceAsCode/compliance-operator/pkg/celcontent"
)

func main() {
	rulesDir := flag.String("rules", "", "Path to the CEL rules directory")
	profilesDir := flag.String("profiles", "", "Path to the CEL profiles directory")
	output := flag.String("output", "", "Output path for the bundled YAML file")
	flag.Parse()

	if *rulesDir == "" || *profilesDir == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "Usage: cel-bundler -rules <dir> -profiles <dir> -output <file>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := celcontent.BundleToFile(*rulesDir, *profilesDir, *output); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %s\n", *output)
}
