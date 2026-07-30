# Direct Garmin transfer dependencies

Podrush builds these open-source libraries from source on first use. The archives
are downloaded from their official GitHub releases, verified before extraction,
and cached under `media/.garmin-mtp/`.

| Library | Version | License | Release archive | SHA-256 |
| --- | --- | --- | --- | --- |
| libusb | 1.0.29 | LGPL-2.1-or-later | https://github.com/libusb/libusb/releases/download/v1.0.29/libusb-1.0.29.tar.bz2 | `5977fc950f8d1395ccea9bd48c06b3f808fd3c2c961b44b0c2e6e29fc3a70a85` |
| libmtp | 1.1.22 | LGPL-2.1-or-later | https://github.com/libmtp/libmtp/releases/download/v1.1.22/libmtp-1.1.22.tar.gz | `c3fcf411aea9cb9643590cbc9df99fa5fe30adcac695024442973d76fa5f87bc` |

The upstream `COPYING` files are installed alongside the locally built
libraries in `media/.garmin-mtp/runtime/licenses/`.
