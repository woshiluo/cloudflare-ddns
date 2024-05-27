# Maintainter: Woshiluo Luo <woshiluo.luo@outlook.com>
pkgname=cloudflare-ddns-git
_pkgname=cloudflare-ddns
pkgver=8aad05
pkgrel=1
pkgdesc="CloudFlare Ddns"
arch=('x86_64' 'i686')
url="https://github.com/woshiluo/cloudflare-ddns"
license=('AGPL3')
makedepends=('git')
source=(git+https://github.com/woshiluo/cloudflare-ddns)

md5sums=('SKIP')

pkgver() {
	cd "$srcdir/$_pkgname"

	echo $(git rev-list --all --max-count=1 | cut -b 1-6)
}

build() {
	cd "$srcdir/$_pkgname"

	cargo build --release
}

package() {
	cd "$srcdir/$_pkgname"

	mkdir -p $pkgdir/usr/bin
	find target/release \
		-maxdepth 1 \
		-executable \
		-type f \
		-exec install -m 755 "{}" "$pkgdir"/usr/bin \;
}
