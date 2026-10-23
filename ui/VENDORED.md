# Third-party files of the web interface

All files below are embedded into the `whawty-nginx-sso` binary so that the
web interface works without internet access. Only add files whose license
allows redistribution in binary form, put the license text next to them and
record them here. The SHA-256 sums are those of the files in this directory.

The icon sprite only contains the icons listed in `UI_ICONS` in the Makefile.
To add an icon or update Lucide or Font Awesome, change `UI_ICONS` or the
`*_VERSION` and `*_SHA256` variables there and run `make ui-icons`.

| File(s) in `assets/` | Project | Version | License | Source |
|---|---|---|---|---|
| `vendor/icons.svg`, all icons except `brand-*` | [Lucide](https://lucide.dev/) | 1.59.0 | ISC, some icons MIT, see `vendor/lucide/LICENSE` | generated from the npm package `lucide-static@1.59.0` with `make ui-icons` |
| `vendor/icons.svg`, the `brand-*` icons | [Font Awesome Free](https://fontawesome.com/) | 7.3.1 | icons CC BY 4.0, see `vendor/fontawesome/LICENSE.txt` | generated from `svgs/brands/` of the npm package `@fortawesome/fontawesome-free@7.3.1` with `make ui-icons` |
| `img/favicon.svg` | [Lucide](https://lucide.dev/) | 1.59.0 | ISC, see `vendor/lucide/LICENSE` | the `shield-house` icon, black or white depending on the browser theme, made by hand |

`css/base.css` is shared with whawty.auth and kept the same in both projects.

The files in `bootstrap/` (Bootstrap 5.0.2) and `fontawesome/` (Font Awesome
Free 6.4.0) are only used by the old templates and are removed together with
them.

SHA-256:

```
89abdaccb4b15871d1c368ac52f75df01701cc5745f65c0e4a5332a59c8120ef  vendor/icons.svg
```
