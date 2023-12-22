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
	"io/fs"
	"os"
	"path"
	"time"

	"github.com/flosch/go-humanize"
	"github.com/flosch/pongo2/v6"
	"github.com/mileusna/useragent"
	"github.com/whawty/nginx-sso/cookie"
)

func init() {
	pongo2.RegisterFilter("fa_icon", filterFontAwesomeIcon)
	pongo2.RegisterFilter("timeuntil", filterTimeuntilTimesince)
	pongo2.RegisterFilter("timesince", filterTimeuntilTimesince)
	pongo2.RegisterFilter("naturaltime", filterTimeuntilTimesince)
}

type filteredFilesystem struct {
	base fs.FS
}

func (f *filteredFilesystem) Open(name string) (fs.File, error) {
	if path.Ext(name) == ".htmpl" {
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
	}
	return f.base.Open(name)
}

type AlertLevel string

const (
	AlertDanger  AlertLevel = "danger"
	AlertWarning AlertLevel = "warning"
	AlertSuccess AlertLevel = "warning"
	AlertInfo    AlertLevel = "info"
)

type Alert struct {
	Level   AlertLevel
	Heading string
	Message string
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
	switch obj.(type) {
	case cookie.AgentInfo:
		return fontAwesomeIconFromAgentInfo(obj.(cookie.AgentInfo), param.String())
	}
	err := fmt.Errorf("object type '%T' is not supported", obj)
	return nil, &pongo2.Error{Sender: "filter:fa_icon", OrigError: err}
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
