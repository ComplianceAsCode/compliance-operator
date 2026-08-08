package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"path/filepath"
	"strings"
)

func main() {
	format := flag.String("format", "makefile", "Output format: makefile, json, or shell")
	flag.Parse()

	// Parse update_csv.go to extract Konflux pull specs
	updateCSVPath := filepath.Join("bundle-hack", "update_csv.go")
	images, err := extractKonfluxImages(updateCSVPath)
	if err != nil {
		log.Fatalf("Failed to extract images: %v", err)
	}

	// Output in requested format
	switch *format {
	case "makefile":
		outputMakefile(images)
	case "shell":
		outputShell(images)
	case "json":
		outputJSON(images)
	default:
		log.Fatalf("Unknown format: %s", *format)
	}
}

type KonfluxImages struct {
	Operator   string
	Content    string
	Openscap   string
	MustGather string
}

func extractKonfluxImages(filepath string) (*KonfluxImages, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filepath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}

	images := &KonfluxImages{}

	// Walk the AST to find variable declarations
	ast.Inspect(node, func(n ast.Node) bool {
		if genDecl, ok := n.(*ast.GenDecl); ok && genDecl.Tok == token.VAR {
			for _, spec := range genDecl.Specs {
				if valueSpec, ok := spec.(*ast.ValueSpec); ok {
					for i, name := range valueSpec.Names {
						if i < len(valueSpec.Values) {
							if basicLit, ok := valueSpec.Values[i].(*ast.BasicLit); ok {
								value := strings.Trim(basicLit.Value, `"`)
								switch name.Name {
								case "konfluxOperatorPullSpec":
									images.Operator = value
								case "konfluxContentPullSpec":
									images.Content = value
								case "konfluxOpenscapPullSpec":
									images.Openscap = value
								case "konfluxMustGatherPullSpec":
									images.MustGather = value
								}
							}
						}
					}
				}
			}
		}
		return true
	})

	// Validate that we found all required images
	if images.Operator == "" || images.Content == "" || images.Openscap == "" || images.MustGather == "" {
		return nil, fmt.Errorf("failed to extract all required image specs")
	}

	return images, nil
}

func outputMakefile(images *KonfluxImages) {
	fmt.Printf("KONFLUX_OPERATOR_IMAGE=%s\n", images.Operator)
	fmt.Printf("KONFLUX_CONTENT_IMAGE=%s\n", images.Content)
	fmt.Printf("KONFLUX_OPENSCAP_IMAGE=%s\n", images.Openscap)
	fmt.Printf("KONFLUX_MUST_GATHER_IMAGE=%s\n", images.MustGather)
}

func outputShell(images *KonfluxImages) {
	fmt.Printf("export KONFLUX_OPERATOR_IMAGE='%s'\n", images.Operator)
	fmt.Printf("export KONFLUX_CONTENT_IMAGE='%s'\n", images.Content)
	fmt.Printf("export KONFLUX_OPENSCAP_IMAGE='%s'\n", images.Openscap)
	fmt.Printf("export KONFLUX_MUST_GATHER_IMAGE='%s'\n", images.MustGather)
}

func outputJSON(images *KonfluxImages) {
	fmt.Printf(`{
  "operator": "%s",
  "content": "%s",
  "openscap": "%s",
  "mustGather": "%s"
}
`, images.Operator, images.Content, images.Openscap, images.MustGather)
}
