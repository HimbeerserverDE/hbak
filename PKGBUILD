# Maintainer: Himbeer <https://github.com/HimbeerserverDE/hbak>

pkgname=hbak
pkgver=0.2.0
pkgrel=1
pkgdesc="Simple distributed backup utility for btrfs."
arch=('x86_64' 'aarch64')
url="https://github.com/HimbeerserverDE/hbak"
license=('GPL-3.0-or-later')
depends=()
makedepends=('rust' 'cargo' 'gcc')
provides=('hbak')
conflicts=('hbak')
source=("${pkgname}-${pkgver}.tar.gz::https://github.com/HimbeerserverDE/hbak/archive/${pkgver}.tar.gz")
sha256sums=('efd474fb2cf2124374a2b352e28a831b6e343acd49643f593f3cdd2096d121d3')


build() {
	cd "${srcdir}/${pkgname}-${pkgver}"
	cargo build --release --all --target-dir "./target"
}

package() {
	cd "${srcdir}/${pkgname}-${pkgver}"

	# Install binaries.
	install -Dm 755 "target/release/${pkgname}" "${pkgdir}/usr/bin/${pkgname}"
	install -Dm 755 "target/release/${pkgname}d" "${pkgdir}/usr/bin/${pkgname}d"
}
