#!/bin/bash

##
## Generates all possible LUKS1 and LUKS2 containers and their hashes
##

# TODO:
#  1. generate some files with multiple keyslots..
#  2. only supports ext4 maybe we want to use different filesystems?
#  3. does LUKS2 also support Argon2d?

OUTPUT_DIR="./luks2-containers-hashcat"
PASSWORD_FILE="./luks2-passwords-hashcat.txt"

MOUNT_DIR="./mnt"

set -euo pipefail

trap 'echo "⚠️  Interrupted. Cleaning up..."; exit 1' SIGINT

# Must be root
if [[ $EUID -ne 0 ]]; then
  echo "❌ This script must be run as root to be able to (loop)mount the LUKS2 containers (use: sudo $0)"
  exit 1
fi

# Check for cryptsetup
if ! command -v cryptsetup &> /dev/null; then
  echo "❌ cryptsetup is not installed."
  echo "➡️  On Ubuntu/Debian, install it with:"
  echo "    sudo apt update && sudo apt install cryptsetup"
  exit 1
fi

# Check for mkfs.ext4
if ! command -v mkfs.ext4 &> /dev/null; then
  echo "❌ mkfs.ext4 is not installed."
  echo "➡️  On Ubuntu/Debian, install it with:"
  echo "    sudo apt update && sudo apt install e2fsprogs"
  exit 1
fi

mkdir -p "$OUTPUT_DIR" "$MOUNT_DIR"
> "$PASSWORD_FILE"  # Clear password file

declare -A CIPHERS=(
  ["aes"]="aes-xts-plain64"
  ["serpent"]="serpent-xts-plain64"
  ["twofish"]="twofish-xts-plain64"
)

HASHES=("sha256" ) #"sha512" "whirlpool") #only sha256 supported for luks2
LUKS_TYPES=( "luks2") #"luks1"

ARGON_KDFS=(
  "argon2i"
  "argon2id"
)

ARGON_TIMES=(4 5 6)
ARGON_MEMORY=(16 32 64 128 256 512 1024)
ARGON_THREADS=(1 2 4 8)

PW_LEN_MIN=8
PS_LEN_MAX=32
size=20

# Generate a random password of length N with letters, digits, and symbols
generate_password() {
  local length=$1
  tr -dc 'A-Za-z0-9!@#$%^&*()-_=+[]{}<>?' < /dev/urandom | head -c "$length"
  echo
}

create_luks_container() {
  local filename="$1"
  local luks_type="$2"
  local cipher="$3"
  local hash="$4"
  local size_mb="$5"
  shift 5
  local extra_opts=("$@")

  # Generate a random password length between 3 and 32 for each container
  local pw_length=$(( RANDOM % (PS_LEN_MAX - PW_LEN_MIN + 1) + PW_LEN_MIN ))
  local PASSWORD
  PASSWORD="hashcat" #$(generate_password "$pw_length")

  echo "🔧 Creating $filename (size ${size_mb}MiB) with password length ${#PASSWORD}..."
  dd if=/dev/zero of="$filename" bs=1M count="$size_mb" status=none

  loopdev=$(losetup --show -f "$filename")

  if cryptsetup luksFormat \
      --batch-mode \
      --type "$luks_type" \
      --cipher "$cipher" \
      --key-size 512 \
      --hash "$hash" \
      "${extra_opts[@]}" \
      "$loopdev" <<< "$PASSWORD"; then
    echo "✅ Formatted: $filename"
  else
    echo "❌ Failed to format: $filename"
    losetup -d "$loopdev"
    rm -f "$filename"
    return
  fi

  name="luks$(basename "$filename" | sha1sum | cut -c1-8)"

  if [ -e "/dev/mapper/$name" ]; then
    echo "⚠️  Device $name already exists. Closing it first."
    cryptsetup close "$name" || true
  fi

  cryptsetup open "$loopdev" "$name" <<< "$PASSWORD"

  mkfs.ext4 -q /dev/mapper/"$name"

  mount_point="$MOUNT_DIR/$name"
  mkdir -p "$mount_point"
  mount /dev/mapper/"$name" "$mount_point"

  echo "Hello from $filename" > "$mount_point/info.txt"
  while ! umount "$mount_point"; do
    echo "Waiting for $mount_point to become free..."
    sleep 1
  done

  cryptsetup close "$name"

  echo "✅ ext4: $filename"

  losetup -D

  # Save password to file with filename as key
  echo "$filename $PASSWORD" >> "$PASSWORD_FILE"
}

# LUKS1 & LUKS2 with hash-based KDFs
for luks_type in "${LUKS_TYPES[@]}"; do
  for cipher_name in "${!CIPHERS[@]}"; do
    cipher=${CIPHERS[$cipher_name]}
    for hash in "${HASHES[@]}"; do
      file="${OUTPUT_DIR}/${luks_type}-${cipher_name}-${hash}-size${size}MiB.img"
      create_luks_container "$file" "$luks_type" "$cipher" "$hash" "$size"
    done
  done
done

# LUKS2 with Argon2 KDFs
for kdf in "${ARGON_KDFS[@]}"; do
  for time in "${ARGON_TIMES[@]}"; do
    for memory in "${ARGON_MEMORY[@]}"; do
      for threads in "${ARGON_THREADS[@]}"; do

        if (( memory >= 512 && threads >= 4 )); then
          continue
        fi

        for cipher_name in "${!CIPHERS[@]}"; do
          cipher=${CIPHERS[$cipher_name]}
          file="${OUTPUT_DIR}/luks2-${cipher_name}-${kdf}-t${time}-m${memory}-p${threads}-size${size}MiB.img"
          create_luks_container "$file" luks2 "$cipher" sha256 "$size" \
            --pbkdf "$kdf" \
            --pbkdf-force-iterations "$time" \
            --pbkdf-memory "$((memory * 1024))" \
            --pbkdf-parallel "$threads"
        done

      done
    done
  done
done

echo "🎉 All containers created and initialized with ext4 in: $OUTPUT_DIR"
echo "🔐 Passwords saved in: $PASSWORD_FILE"

echo 'Generating hashes from .img'
ls $OUTPUT_DIR*.img | while read f; do echo $f; tools/luks2hashcat.py $f | grep -vE '^[0-9]+$' > $f.hash
echo 'Done generating hashes from .img'