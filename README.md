hbak
====

Distributed backup utility for btrfs.

This project aims to automate decentralised and end-to-end encrypted
backups of all of my machines and to provide a simple command-line interface
for administration and recovery.

Architecture
============

This program is designed primarily for use in an internal home network.
There will be support for both push and pull models in order to enable usage
across unidirectional firewalls, making it possible to use this tool
on multiple VLANs or even the public internet.

All backups will be encrypted before leaving the host they originated from.
The nodes will also transmit encrypted metadata to handle multi-host setups,
timestamps and storage locations.

Nodes will mutually authenticate using pre-shared secrets.

The backups themselves will be btrfs snapshots with some being fully exported
and others being incremental with respect to the latest full backup at the time
of their creation.

The `/etc/fstab` file should be handled in some way, though the final solution
doesn't exist yet. It could be updated automatically or manually using a
command-line flag or subcommand, or be left to the user with a warning message.

Components
----------

There are two main components:

* hbak: The main snapshotter handling encryption and file distribution.
* hbakd: A background process responsible for handling push and pull requests.

Both programs require root privileges. Automation is handled externally
by tools like cron or anacron.
