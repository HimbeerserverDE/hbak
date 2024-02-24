# Maintainer: Himbeer <https://github.com/HimbeerserverDE/hbak>

pkgname=hbak
pkgver=0.3.3
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
sha512sums=('ec15491c06b93a9bf216c39f4548488b6e84fe2e48a9e28cb2e3854567ba66b1fa61e540776590703b85bd8c987904f243f158c3dc1660502dda397e067a8f0b')


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
