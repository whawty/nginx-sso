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

package ui

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/flosch/pongo2/v6"
	"github.com/mileusna/useragent"
	"github.com/whawty/nginx-sso/cookie"
)

func TestUserAgentIcon(t *testing.T) {
	tests := []struct {
		ua               string
		name, os, device string
		deviceType       string
	}{
		{"Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
			"brand-firefox-browser", "brand-linux", "monitor", cookie.DeviceTypeDesktop},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
			"brand-edge", "brand-windows", "monitor", cookie.DeviceTypeDesktop},
		{"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36",
			"brand-chrome", "brand-android", "smartphone", cookie.DeviceTypeMobile},
		{"Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
			"brand-safari", "brand-apple", "tablet", cookie.DeviceTypeTablet},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 OPR/120.0.0.0",
			"brand-opera", "brand-apple", "monitor", cookie.DeviceTypeDesktop},
		{"Go-http-client/1.1", "globe", "circle-help", "bot", cookie.DeviceTypeBot},
		{"", "globe", "circle-help", "circle-help", "unknown"},
	}
	for _, test := range tests {
		ua := useragent.Parse(test.ua)
		ai := cookie.AgentInfo{Name: ua.Name, OS: ua.OS, DeviceType: test.deviceType}
		for attribute, want := range map[string]string{"Name": test.name, "OS": test.os, "DeviceType": test.device} {
			got, err := userAgentIcon(ai, attribute)
			if err != nil || got != want {
				t.Errorf("%q (%+v): %s icon is %q (error: %v), want %q", test.ua, ai, attribute, got, err, want)
			}
		}
	}

	if _, err := userAgentIcon(cookie.AgentInfo{}, "Version"); err == nil {
		t.Error("unknown attribute: no error")
	}
}

// All icons the filter returns must be in the sprite, see UI_ICONS in the Makefile.
func TestUserAgentIconsAreInSprite(t *testing.T) {
	sprite, err := fs.ReadFile(Assets, "vendor/icons.svg")
	if err != nil {
		t.Fatal(err)
	}
	icons := []string{"globe", "circle-help"}
	for _, m := range []map[string]string{agentNameIcons, agentOSIcons, deviceTypeIcons} {
		for _, icon := range m {
			icons = append(icons, icon)
		}
	}
	for _, icon := range icons {
		if !strings.Contains(string(sprite), `<symbol id="`+icon+`"`) {
			t.Errorf("icon %q is not in the sprite", icon)
		}
	}
}

func TestFilterUserAgentIcon(t *testing.T) {
	ctx := pongo2.Context{"agent": cookie.AgentInfo{Name: useragent.Firefox, OS: useragent.Linux, DeviceType: cookie.DeviceTypeDesktop}}

	tpl := pongo2.Must(pongo2.FromString(`{{ agent|ua_icon:"Name" }} {{ agent|ua_icon:"OS" }} {{ agent|ua_icon:"DeviceType" }}`))
	got, err := tpl.Execute(ctx)
	if want := "brand-firefox-browser brand-linux monitor"; err != nil || got != want {
		t.Errorf("got %q (error: %v), want %q", got, err, want)
	}

	for _, src := range []string{`{{ agent|ua_icon:"Version" }}`, `{{ "Firefox"|ua_icon:"Name" }}`} {
		if _, err := pongo2.Must(pongo2.FromString(src)).Execute(ctx); err == nil {
			t.Errorf("%s: no error", src)
		}
	}
}
