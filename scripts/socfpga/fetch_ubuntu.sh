#!/bin/bash

UBUNTU_URL="http://cdimage.ubuntu.com/releases/16.04/release"
UBUNTU_FILE="ubuntu-16.04.4-preinstalled-server-armhf+raspi2"

# handy functions for driving losetup, based on
# https://stackoverflow.com/a/39675265

los() {
  img="$1"
  dev="$(sudo losetup --show -f -P "$img")"
  for part in "$dev"?*; do
    num=${part##${dev}p}
    dst="mnt/$num"
    echo "Found image partition $num, mounting $part at $dst"
    mkdir -p "$dst"
    sudo mount "$part" "$dst"
  done
  loopdev="$dev"
}

losd() {
  dev="$1"
  for part in "$dev"?*; do
    num=${part##${dev}p}
    dst="mnt/$num"
    echo "Found image partition $num, unmounting $part at $dst"
    sudo umount "$part" "$dst"
  done
  sudo losetup -d "$dev"
}


wget -c $UBUNTU_URL/$UBUNTU_FILE.img.xz
unxz $UBUNTU_FILE.img.xz
los $UBUNTU_FILE.img
echo $loopdev
#losd $loopdev
