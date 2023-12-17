#! /bin/sh

find_partition_uuid() {
	findmnt -nso UUID -M /
}

umount_all() {
	umount /mnt/hbak
	sleep 1
	mountpoint -q /mnt/hbak && umount_all
}

HOST=$(hostname)

read -p "Enter new passphrase: " -s PASSPHRASE && echo
read -p "Enter subvolumes to backup: " SUBVOLS
read -p "Enter remotes to sync to: " REMOTES

mkdir -p /etc/hbak.d
echo "${PASSPHRASE}" > /etc/hbak.d/passphrase
echo "${SUBVOLS}" > /etc/hbak.d/subvolumes
echo "${REMOTES}" > /etc/hbak.d/remotes

chmod 0700 /etc/hbak.d
chmod 0600 /etc/hbak.d/*
chown -R root:root /etc/hbak.d

mkdir -p /mnt/hbak
mount -o compress=zstd UUID=$(find_partition_uuid) /mnt/hbak

trap umount_all INT

btrfs subvolume create /mnt/hbak/snapshots
btrfs subvolume create /mnt/hbak/backups

for SUBVOL in ${SUBVOLS}; do
	TS=$(date +%Y%m%d%H%M%S)

	btrfs subvolume snapshot -r /mnt/hbak/${SUBVOL} /mnt/hbak/snapshots/${SUBVOL}_${TS}

	for REMOTE in ${REMOTES}; do
		(echo "TX ${HOST}_full_${SUBVOL}_${TS}"; btrfs send /mnt/hbak/snapshots/${SUBVOL}_${TS} | pv | gpg --batch --symmetric -a --cipher-algo AES256 --passphrase-file /etc/hbak.d/passphrase) | nc -N ${REMOTE} 45545
	done
done

umount_all
