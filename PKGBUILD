# Maintainer: Himbeer <https://github.com/HimbeerserverDE/hbak>

pkgname=hbak
pkgver=0.3.2
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
sha512sums=('b0ad382043a01eff8dc6b1ef0f68605467662892cd2339e30a37e6f1fe58360c64083dfef0a13ff9e0bd784be3d3c7e8a96f06db59ccde55892eee8e814dda99')


build() {
	cd "${builddir}"
	cargo build --release --all --target-dir "./target"
}

package() {
	cd "${builddir}"

	# Install binaries.
	install -Dm 755 "target/release/${pkgname}" "${pkgdir}/usr/bin/${pkgname}"
	install -Dm 755 "target/release/${pkgname}d" "${pkgdir}/usr/bin/${pkgname}d"
}
