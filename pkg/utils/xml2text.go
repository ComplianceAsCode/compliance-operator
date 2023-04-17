package utils

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"text/template"

	"github.com/antchfx/xmlquery"
	"github.com/jaytaylor/html2text"
	"github.com/pkg/errors"
)

func XmlNodeAsMarkdownPreRender(node *xmlquery.Node, needsSpace bool) string {
	return xmlToMarkdown(node.OutputXML(false), true, needsSpace)
}

func XmlNodeAsMarkdown(node *xmlquery.Node) string {
	return xmlToMarkdown(node.OutputXML(false), false, false)
}

func xmlToMarkdown(in string, preRender bool, needsSpace bool) string {

	text, err := html2text.FromString(xmlToHtml(in, preRender, needsSpace), html2text.Options{PrettyTables: true, OmitLinks: false})
	if err != nil {
		return in
	}
	return text
}

func xmlToHtml(in string, preRender bool, needsSpace bool) string {
	builder := strings.Builder{}
	decoder := xml.NewDecoder(strings.NewReader(in))
	for {
		// Read tokens from the XML document in a stream.
		t, err := decoder.Token()
		if err == io.EOF {
			break
		} else if err != nil {
			// ignore errors and try to format as much as possible
			continue
		}

		switch tok := t.(type) {
		case xml.StartElement:
			if preRender && tok.Name.Local == "sub" && len(tok.Attr) > 1 {
				if strings.HasPrefix(tok.Attr[0].Value, valuePrefix) {
					// Have the check in nested if statment to avoid array out of bond
					builder.WriteString(formateXccdfVar(tok.Attr[0].Value, needsSpace))
				} else {
					builder.WriteString(formatElement(tok.Name, "<"))
				}
			} else {
				// This is a special case so that we can look for links in <a> tags.
				builder.WriteString(formatStartElement(tok))
			}
		case xml.EndElement:
			builder.WriteString(formatElement(tok.Name, "</"))
		case xml.CharData:
			builder.Write(tok)
		}
	}

	return builder.String()
}

func formateXccdfVar(in string, needsSpace bool) string {
	if needsSpace {
		return " {{." + strings.TrimPrefix(in, valuePrefix) + "}} "
	}
	return "{{." + strings.TrimPrefix(in, valuePrefix) + "}}"
}

func formatElement(elName xml.Name, tag string) string {
	// just pass non-html tags through
	var t string
	if elName.Space != "html" {
		t = tag + elName.Space + ":" + elName.Local + ">"
	} else {
		// enclose pre in a paragraph to force a line break
		if elName.Local == "pre" && tag == "<" {
			t = tag + "p>"
		}

		t += tag + elName.Local + ">"

		if elName.Local == "pre" && tag == "</" {
			t += tag + "p>"
		}
	}

	return t
}

func formatStartElement(e xml.StartElement) string {
	t := formatElement(e.Name, "<")

	if t == "<a>" {
		// find the link
		h := e.Attr[0].Name.Local
		l := e.Attr[0].Value
		t = "<" + e.Name.Local + " " + h + "=" + "\"" + l + "\"" + ">"
	}
	return t
}

func RenderValues(in string, valuesList map[string]string) (string, []string, error) {
	t, err := template.New("").Option("missingkey=zero").Parse(in)

	if err != nil {
		return in, nil, errors.Wrap(err, "wrongly formatted context: ")
	}

	buf := &bytes.Buffer{}
	err = t.Execute(buf, valuesList)
	if err != nil {
		return in, nil, errors.Wrap(err, "error while parsing variables into values: ")
	}
	out := buf.String()

	return out, getParsedValueName(t), nil
}
