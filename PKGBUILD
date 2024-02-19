# Maintainer: Himbeer <https://github.com/HimbeerserverDE/hbak>

pkgname=hbak
pkgver=0.3.0
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
sha512sums=('0cd0948c47a1456e916c23282c4a66d4029ee3388415dea6084cb7738b1f8536e8f9437ca919c4c4a2f4db6414203ccad0d8f90dfc05a8c355991bee6c39533d')


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
