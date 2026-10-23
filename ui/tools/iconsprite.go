//
// Copyright (c) 2026 whawty contributors (see AUTHORS file)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of whawty.nginx-sso nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

//go:build ignore

// iconsprite builds the SVG sprite of the web interface from the icons of the
// npm packages lucide-static and @fortawesome/fontawesome-free. It is not part
// of the build, use `make ui-icons` which downloads the packages and runs
//
//	go run ui/tools/iconsprite.go -lucide <unpacked package> -fontawesome <unpacked package> \
//	    -out ui/assets/vendor/icons.svg <icon-name>...
//
// The versions of the packages and the list of icons are set in the Makefile.
// Icon names starting with brand- are brand logos of Font Awesome (brand-linux
// is svgs/brands/linux.svg), all others are Lucide icons. Every icon becomes
// a <symbol> with its name as id, the templates use them with
// <svg><use href="ui/vendor/icons.svg#<icon-name>"/></svg>.
package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const brandPrefix = "brand-"

type icon struct {
	Attrs []xml.Attr `xml:",any,attr"`
	Inner string     `xml:",innerxml"`
}

// attributes of the root element which are not copied to the <symbol>
var dropAttrs = map[string]bool{"class": true, "width": true, "height": true, "xmlns": true}

var (
	commentRe     = regexp.MustCompile(`(?s)<!--.*?-->`)
	betweenTagsRe = regexp.MustCompile(`>\s+<`)
)

// readIcon returns the icon in file as <symbol> with the given id. Lucide
// icons are outlines which carry fill and stroke on the root element, Font
// Awesome icons are filled shapes, so fill is set to currentColor for them if
// the icon doesn't set it.
func readIcon(file, id string) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	var ic icon
	if err := xml.Unmarshal(data, &ic); err != nil {
		return "", fmt.Errorf("%s: %v", file, err)
	}

	var attrs []string
	hasFill := false
	for _, a := range ic.Attrs {
		if a.Name.Space != "" || dropAttrs[a.Name.Local] {
			continue
		}
		hasFill = hasFill || a.Name.Local == "fill"
		var value strings.Builder
		if err := xml.EscapeText(&value, []byte(a.Value)); err != nil {
			return "", err
		}
		attrs = append(attrs, fmt.Sprintf(`%s="%s"`, a.Name.Local, value.String()))
	}
	if !hasFill {
		attrs = append(attrs, `fill="currentColor"`)
	}
	inner := commentRe.ReplaceAllString(ic.Inner, "")
	inner = betweenTagsRe.ReplaceAllString(strings.TrimSpace(inner), "><")
	return fmt.Sprintf(`<symbol id="%s" %s>%s</symbol>`, id, strings.Join(attrs, " "), inner), nil
}

func packageVersion(dir, name string) string {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return "unknown version"
	}
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil || pkg.Name != name {
		return "unknown version"
	}
	return pkg.Version
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func main() {
	lucide := flag.String("lucide", "", "directory of the unpacked lucide-static package (contains icons/)")
	fontawesome := flag.String("fontawesome", "", "directory of the unpacked @fortawesome/fontawesome-free package (contains svgs/brands/)")
	out := flag.String("out", "", "file to write the sprite to")
	flag.Parse()
	names := flag.Args()
	if *lucide == "" || *fontawesome == "" || *out == "" || len(names) == 0 {
		fmt.Fprintln(os.Stderr, "usage: go run ui/tools/iconsprite.go -lucide <lucide-static> -fontawesome <fontawesome-free> -out <sprite.svg> <icon-name>...")
		os.Exit(2)
	}
	sort.Strings(names)

	var sprite strings.Builder
	sprite.WriteString(`<svg xmlns="http://www.w3.org/2000/svg">` + "\n")
	fmt.Fprintf(&sprite, "<!-- Icons: Lucide %s (https://lucide.dev), ISC License, some icons MIT License, see lucide/LICENSE.\n",
		packageVersion(*lucide, "lucide-static"))
	fmt.Fprintf(&sprite, "     Brand logos (brand-*): Font Awesome Free %s by @fontawesome - https://fontawesome.com\n",
		packageVersion(*fontawesome, "@fortawesome/fontawesome-free"))
	sprite.WriteString("     License - https://fontawesome.com/license/free (Icons: CC BY 4.0), see fontawesome/LICENSE.txt.\n")
	sprite.WriteString("     Generated by ui/tools/iconsprite.go, do not edit. -->\n")
	for _, name := range names {
		file := filepath.Join(*lucide, "icons", name+".svg")
		if brand, ok := strings.CutPrefix(name, brandPrefix); ok {
			file = filepath.Join(*fontawesome, "svgs", "brands", brand+".svg")
		}
		symbol, err := readIcon(file, name)
		if err != nil {
			fail(err)
		}
		sprite.WriteString(symbol + "\n")
	}
	sprite.WriteString("</svg>\n")

	if err := os.WriteFile(*out, []byte(sprite.String()), 0644); err != nil {
		fail(err)
	}
}
