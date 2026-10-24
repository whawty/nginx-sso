//
// Copyright (c) 2023 whawty contributors (see AUTHORS file)
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
	"errors"
	"fmt"
	"time"

	"github.com/flosch/go-humanize"
	"github.com/flosch/pongo2/v6"
	"github.com/mileusna/useragent"
	"github.com/whawty/nginx-sso/cookie"
)

func init() {
	pongo2.RegisterFilter("fa_icon", filterFontAwesomeIcon)        //nolint:errcheck
	pongo2.RegisterFilter("ua_icon", filterUserAgentIcon)          //nolint:errcheck
	pongo2.RegisterFilter("timeuntil", filterTimeuntilTimesince)   //nolint:errcheck
	pongo2.RegisterFilter("timesince", filterTimeuntilTimesince)   //nolint:errcheck
	pongo2.RegisterFilter("naturaltime", filterTimeuntilTimesince) //nolint:errcheck
}

type AlertLevel string

const (
	AlertDanger  AlertLevel = "danger"
	AlertWarning AlertLevel = "warning"
	AlertSuccess AlertLevel = "success"
	AlertInfo    AlertLevel = "info"
)

type Alert struct {
	Level   AlertLevel
	Heading string
	Message string
}

// Class returns the CSS class of the alert, see css/base.css and css/app.css.
func (a Alert) Class() string {
	if a.Level == AlertDanger {
		return "alert-error"
	}
	return "alert-" + string(a.Level)
}

// Icon returns the name of the icon of the alert in the sprite.
func (a Alert) Icon() string {
	switch a.Level {
	case AlertWarning:
		return "triangle-alert"
	case AlertSuccess:
		return "circle-check"
	case AlertInfo:
		return "info"
	default:
		return "circle-alert"
	}
}

func fontAwesomeIconFromAgentInfo(ai cookie.AgentInfo, attribute string) (*pongo2.Value, *pongo2.Error) {
	switch attribute {
	case "Name":
		switch ai.Name {
		case useragent.Firefox:
			return pongo2.AsSafeValue("fa-brands fa-firefox"), nil
		case useragent.HeadlessChrome:
			fallthrough
		case useragent.Chrome:
			return pongo2.AsSafeValue("fa-brands fa-chrome"), nil
		case useragent.OperaMini:
			fallthrough
		case useragent.OperaTouch:
			fallthrough
		case useragent.Opera:
			return pongo2.AsSafeValue("fa-brands fa-opera"), nil
		case useragent.Safari:
			return pongo2.AsSafeValue("fa-brands fa-safari"), nil
		case useragent.InternetExplorer:
			return pongo2.AsSafeValue("fa-brands fa-internet-explorer"), nil
		case useragent.Edge:
			return pongo2.AsSafeValue("fa-brands fa-edge"), nil
		default:
			return pongo2.AsSafeValue("fa-solid fa-question"), nil
		}
	case "OS":
		switch ai.OS {
		case useragent.Linux:
			return pongo2.AsSafeValue("fa-brands fa-linux"), nil
		case useragent.WindowsPhone:
			fallthrough
		case useragent.Windows:
			return pongo2.AsSafeValue("fa-brands fa-windows"), nil
		case useragent.Android:
			return pongo2.AsSafeValue("fa-brands fa-android"), nil
		case useragent.MacOS:
			fallthrough
		case useragent.IOS:
			return pongo2.AsSafeValue("fa-brands fa-apple"), nil
		case useragent.FreeBSD:
			return pongo2.AsSafeValue("fa-brands fa-freebsd"), nil
		case useragent.ChromeOS:
			return pongo2.AsSafeValue("fa-brands fa-chrome"), nil
		case useragent.BlackBerry:
			return pongo2.AsSafeValue("fa-brands fa-blackberry"), nil
		default:
			return pongo2.AsSafeValue("fa-solid fa-question"), nil
		}
	case "DeviceType":
		switch ai.DeviceType {
		case cookie.DeviceTypeMobile:
			return pongo2.AsSafeValue("fa-solid fa-mobile"), nil
		case cookie.DeviceTypeTablet:
			return pongo2.AsSafeValue("fa-solid fa-tablet"), nil
		case cookie.DeviceTypeDesktop:
			return pongo2.AsSafeValue("fa-solid fa-desktop"), nil
		case cookie.DeviceTypeBot:
			return pongo2.AsSafeValue("fa-solid fa-robot"), nil
		default:
			return pongo2.AsSafeValue("fa-solid fa-question"), nil
		}
	}
	err := fmt.Errorf("cookie.AgentInfo has no attribute '%s'", attribute)
	return nil, &pongo2.Error{Sender: "filter:fa_icon", OrigError: err}
}

func filterFontAwesomeIcon(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
	obj := in.Interface()
	switch obj := obj.(type) {
	case cookie.AgentInfo:
		return fontAwesomeIconFromAgentInfo(obj, param.String())
	}
	err := fmt.Errorf("object type '%T' is not supported", obj)
	return nil, &pongo2.Error{Sender: "filter:fa_icon", OrigError: err}
}

// Icons of the sprite assets/vendor/icons.svg for the browser, operating
// system and type of device of a session. All icons used here must be listed
// in UI_ICONS in the Makefile.
var (
	agentNameIcons = map[string]string{
		useragent.Chrome:           "brand-chrome",
		useragent.HeadlessChrome:   "brand-chrome",
		useragent.Edge:             "brand-edge",
		useragent.Firefox:          "brand-firefox-browser",
		useragent.InternetExplorer: "brand-internet-explorer",
		useragent.Msie:             "brand-internet-explorer",
		useragent.Opera:            "brand-opera",
		useragent.OperaMini:        "brand-opera",
		useragent.OperaTouch:       "brand-opera",
		useragent.Safari:           "brand-safari",
		useragent.MobileSafari:     "brand-safari",
	}
	agentOSIcons = map[string]string{
		useragent.Android:        "brand-android",
		useragent.BlackBerry:     "brand-blackberry",
		useragent.ChromeOS:       "brand-chrome",
		useragent.CrOS:           "brand-chrome",
		useragent.FreeBSD:        "brand-freebsd",
		useragent.IOS:            "brand-apple",
		useragent.MacOS:          "brand-apple",
		useragent.Linux:          "brand-linux",
		useragent.Windows:        "brand-windows",
		useragent.WindowsNT:      "brand-windows",
		useragent.WindowsPhone:   "brand-windows",
		useragent.WindowsPhoneOS: "brand-windows",
	}
	deviceTypeIcons = map[string]string{
		cookie.DeviceTypeMobile:  "smartphone",
		cookie.DeviceTypeTablet:  "tablet",
		cookie.DeviceTypeDesktop: "monitor",
		cookie.DeviceTypeBot:     "bot",
	}
)

// userAgentIcon returns the name of the icon for the given attribute of ai
// (Name, OS or DeviceType), or a generic icon if there is none.
func userAgentIcon(ai cookie.AgentInfo, attribute string) (string, error) {
	icons, value, fallback := map[string]string(nil), "", ""
	switch attribute {
	case "Name":
		icons, value, fallback = agentNameIcons, ai.Name, "globe"
	case "OS":
		icons, value, fallback = agentOSIcons, ai.OS, "circle-help"
	case "DeviceType":
		icons, value, fallback = deviceTypeIcons, ai.DeviceType, "circle-help"
	default:
		return "", fmt.Errorf("cookie.AgentInfo has no attribute '%s'", attribute)
	}
	if icon, ok := icons[value]; ok {
		return icon, nil
	}
	return fallback, nil
}

// filterUserAgentIcon is the filter ua_icon:
// {{ session.Agent | ua_icon:"Name" }} is the name of the icon of the browser
// in the sprite, i.e. brand-firefox-browser, use OS or DeviceType for the
// operating system and the type of device.
func filterUserAgentIcon(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
	ai, ok := in.Interface().(cookie.AgentInfo)
	if !ok {
		err := fmt.Errorf("object type '%T' is not supported", in.Interface())
		return nil, &pongo2.Error{Sender: "filter:ua_icon", OrigError: err}
	}
	icon, err := userAgentIcon(ai, param.String())
	if err != nil {
		return nil, &pongo2.Error{Sender: "filter:ua_icon", OrigError: err}
	}
	return pongo2.AsValue(icon), nil
}

// This is a copy from: https://github.com/flosch/pongo2-addons which sadly does not support pongo2/v6 yet...
func filterTimeuntilTimesince(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
	basetime, isTime := in.Interface().(time.Time)
	if !isTime {
		return nil, &pongo2.Error{
			Sender:    "filter:timeuntil/timesince",
			OrigError: errors.New("time-value is not a time.Time-instance"),
		}
	}
	var paramtime time.Time
	if !param.IsNil() {
		paramtime, isTime = param.Interface().(time.Time)
		if !isTime {
			return nil, &pongo2.Error{
				Sender:    "filter:timeuntil/timesince",
				OrigError: errors.New("time-parameter is not a time.Time-instance"),
			}
		}
	} else {
		paramtime = time.Now()
	}

	return pongo2.AsValue(humanize.TimeDuration(basetime.Sub(paramtime))), nil
}
