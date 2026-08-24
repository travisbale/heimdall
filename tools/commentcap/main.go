// Command commentcap fails on comment blocks longer than the convention allows.
//
// An in-body comment gets two lines: it describes code that will change, and the code should
// be saying it. A doc comment gets five, being the exported contract godoc renders. Keeping a
// longer block means saying why, on a line a reviewer sees:
//
//	//commentcap:allow -- the four states this maps are not evident from the switch
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

const (
	bodyMax = 2
	docMax  = 5

	allowPrefix = "commentcap:allow"
)

// directives are machinery rather than prose: counted, they pad the block they belong to and
// push the report onto a line the allow directive cannot reach.
var directives = []string{"go:", "nolint", "lint:", "+build", "commentcap:"}

// body strips the marker and the space gofmt may have put after it. A directive gofmt does not
// recognise — anything with a hyphen before the colon — comes back spaced, so matching the raw
// text would quietly stop working the first time the file was formatted.
func body(text string) string {
	return strings.TrimSpace(strings.TrimPrefix(text, "//"))
}

func isDirective(text string) bool {
	for _, d := range directives {
		if strings.HasPrefix(body(text), d) {
			return true
		}
	}
	return false
}

type finding struct {
	pos   token.Position
	lines int
	max   int
	kind  string
}

func main() {
	roots := os.Args[1:]
	if len(roots) == 0 {
		roots = []string{"."}
	}

	var findings []finding
	var checked int
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if name := d.Name(); name == "vendor" || name == ".git" || name == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			fs, err := check(path)
			if err != nil {
				return err
			}
			checked++
			findings = append(findings, fs...)
			return nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "commentcap:", err)
			os.Exit(2)
		}
	}

	for _, f := range findings {
		fmt.Printf("%s:%d:%d: %s comment is %d lines, over the %d this repo allows. Shorten it, or keep it with %s -- <reason>\n",
			f.pos.Filename, f.pos.Line, f.pos.Column, f.kind, f.lines, f.max, "//"+allowPrefix)
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "\ncommentcap: %d over the cap in %d files\n", len(findings), checked)
		os.Exit(1)
	}
}

func check(path string) ([]finding, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Generated files carry the standard header and are nobody's prose to fix.
	if generated(src) {
		return nil, nil
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	docs := docGroups(file)
	lineStarts := ownLineOffsets(src)

	var findings []finding
	for _, group := range file.Comments {
		max, kind := bodyMax, "in-body"
		if docs[group] {
			max, kind = docMax, "doc"
		}
		lines, allowed := 0, false
		for _, c := range group.List {
			// A comment after code annotates that line rather than the block, and go/ast has
			// already put it in a group of its own unless several share the line.
			if !lineStarts[fset.Position(c.Pos()).Offset] {
				continue
			}
			if strings.HasPrefix(body(c.Text), allowPrefix) {
				// A bare allow is not an allow: the reason is the point of it.
				reason := strings.TrimSpace(strings.TrimPrefix(body(c.Text), allowPrefix))
				if strings.HasPrefix(reason, "--") && strings.TrimSpace(strings.TrimPrefix(reason, "--")) != "" {
					allowed = true
				}
				continue
			}
			if isDirective(c.Text) {
				continue
			}
			lines += prose(c.Text)
		}
		if !allowed && lines > max {
			findings = append(findings, finding{fset.Position(group.Pos()), lines, max, kind})
		}
	}
	return findings, nil
}

func generated(src []byte) bool {
	head := src
	if len(head) > 512 {
		head = head[:512]
	}
	return strings.Contains(string(head), "Code generated") && strings.Contains(string(head), "DO NOT EDIT")
}

// docGroups collects the comment groups godoc renders: those attached to a top-level
// declaration, or to the specs and fields inside one. A comment on a local var is in-body
// prose whatever the AST calls it.
func docGroups(file *ast.File) map[*ast.CommentGroup]bool {
	docs := map[*ast.CommentGroup]bool{}
	add := func(g *ast.CommentGroup) {
		if g != nil {
			docs[g] = true
		}
	}
	add(file.Doc)
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			add(d.Doc)
		case *ast.GenDecl:
			add(d.Doc)
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.ValueSpec:
					add(s.Doc)
				case *ast.TypeSpec:
					add(s.Doc)
					fields(s.Type, add)
				}
			}
		}
	}
	return docs
}

func fields(expr ast.Expr, add func(*ast.CommentGroup)) {
	var list *ast.FieldList
	switch t := expr.(type) {
	case *ast.StructType:
		list = t.Fields
	case *ast.InterfaceType:
		list = t.Methods
	default:
		return
	}
	if list == nil {
		return
	}
	for _, f := range list.List {
		add(f.Doc)
		fields(f.Type, add)
	}
}

// ownLineOffsets marks every byte offset that begins a line whose content up to that point is
// only whitespace — which is how a comment that stands alone is told from one after code.
func ownLineOffsets(src []byte) map[int]bool {
	own := map[int]bool{}
	lineStart := 0
	blank := true
	for i := 0; i <= len(src); i++ {
		if i == len(src) || src[i] == '\n' {
			lineStart = i + 1
			blank = true
			continue
		}
		if blank && (src[i] == ' ' || src[i] == '\t') {
			continue
		}
		if blank {
			own[i] = true
			blank = false
		}
	}
	_ = lineStart
	return own
}

// divider reports a rule drawn in punctuation. It separates sections rather than saying
// anything, so counting it would charge a banner three lines for one word of content.
func divider(line string) bool {
	if len(line) < 3 {
		return false
	}
	for _, r := range line {
		if r != rune(line[0]) {
			return false
		}
	}
	return !alphanumeric(line[0])
}

func alphanumeric(b byte) bool {
	return ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') || ('0' <= b && b <= '9')
}

// prose counts the lines a reader reads. Delimiters are not prose: counting /** and */ leaves
// a two-line budget no room for a comment at all.
func prose(text string) int {
	if !strings.HasPrefix(text, "/*") {
		line := strings.TrimSpace(strings.TrimPrefix(text, "//"))
		if line == "" || divider(line) {
			return 0
		}
		return 1
	}
	n := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "/*")
		line = strings.TrimSuffix(line, "*/")
		line = strings.TrimSpace(strings.TrimPrefix(line, "*"))
		if line != "" && !divider(line) {
			n++
		}
	}
	return n
}
