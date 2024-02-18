# Maintainer: Himbeer <https://github.com/HimbeerserverDE/hbak>

pkgname=hbak
pkgver=0.2.1
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
sha256sums=('dc0e5edc0b827aa5f20d59a3bf09b45c8709f2bad8bc02fee15286ced51c496b')


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
