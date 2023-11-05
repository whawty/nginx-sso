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

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"

	"github.com/urfave/cli"
	"github.com/whawty/nginx-sso/cookie"
)

var (
	wl  = log.New(os.Stdout, "[whawty.nginx-sso]\t", log.LstdFlags)
	wdl = log.New(ioutil.Discard, "[whawty.nginx-sso dbg]\t", log.LstdFlags)
)

func init() {
	if _, exists := os.LookupEnv("WHAWTY_NGINX_SSO_DEBUG"); exists {
		wdl.SetOutput(os.Stderr)
	}
}

func cmdRun(c *cli.Context) error {
	conf, err := readConfig(c.GlobalString("config"))
	if err != nil {
		return cli.NewExitError(err.Error(), 1)
	}

	cookies, err := cookie.NewController(&conf.Cookie, wl, wdl)
	if err != nil {
		return cli.NewExitError(err.Error(), 2)
	}

	webAddrs := c.StringSlice("web-addr")
	var wg sync.WaitGroup
	for _, webAddr := range webAddrs {
		a := webAddr
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runWebAddr(a, &conf.Web, cookies); err != nil {
				fmt.Printf("warning running web interface(%s) failed: %s\n", a, err)
			}
		}()
	}
	wg.Wait()

	return cli.NewExitError(fmt.Sprintf("shutting down since all listening sockets have closed."), 0)
}

func main() {
	app := cli.NewApp()
	app.Name = "whawty-nginx-sso"
	app.Version = "0.1"
	app.Usage = "simple SSO for nginx"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Value:  "/etc/whawty/nginx-sso.yaml",
			Usage:  "path to the configuration file",
			EnvVar: "WHAWTY_NGINX_SSO_CONFIG",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:  "run",
			Usage: "run the sso backend",
			Flags: []cli.Flag{
				cli.StringSliceFlag{
					Name:   "web-addr",
					Usage:  "address to listen on for web API",
					EnvVar: "WHAWTY_NGINX_SSO_WEB_ADDR",
				},
			},
			Action: cmdRun,
		},
	}

	wdl.Printf("calling app.Run()")
	app.Run(os.Args)
}
