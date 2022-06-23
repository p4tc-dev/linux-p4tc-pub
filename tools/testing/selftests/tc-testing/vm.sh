#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

help() {
   cat <<EOF
Usage: $0 [-h] [-i <bzImage>] [-c vCPU] [-m vRAM] [-j JOBS] [-f config] [-s] [-g] [-d] -- [<command>]

Recompile the current kernel, turning on all tc related options in the current .config,
and run the provided command. The original .config file is always preserved.
If no command is provided, "$DEFAULT_CMD" is run inside the VM.
Options:
        -h            Display this message.
        -a            Architecture to use.
        -r            Root filesystem to use.
        -i            Precompiled bzImage to use.
        -c            Number of vCPUs to use.
        -m            Size of vRAM to use.
        -j            Number of compilation jobs.
        -f            Kernel configuration file to use.
                      Defaults to "$KCONFIG".
        -s            Start an interactive shell inside the VM.
                      No command is run inside the VM.
        -g            Generate a default kernel config if needed.
        -d            Dry run. Also prints the QEMU command line.
EOF
}

verify_arch() {
   case "$1" in
      x86)
         QEMU_ARCH="i386"
         LINUX_ARCH="x86"
         ;;
      x86_64)
         QEMU_ARCH="x86_64"
         LINUX_ARCH="x86"
         ;;
      s390x)
         QEMU_ARCH="s390x"
         LINUX_ARCH="s390"
         ;;
      *)
         echo "archicteture $1 is not supported"
         exit 1
         ;;
   esac
}

# Reconfigure and recompile the kernel under $KDIR.
# The original configuration file is preserved.
recrec() {
   if [ "$CROSS" == "y" ]; then
      echo "Refusing to cross compile the kernel"
      echo "Provide a pre compiled bzImage"
      exit 0
   fi

   # 'make' command
   MAKE="make -C $KDIR -j $JOBS"

   if ! [ -f "$KCONFIG" ]; then
      if [ "$KCONFIG_GEN" == "y" ]; then
         echo "Generating default kernel .config"
         ${MAKE} defconfig
         ${MAKE} kvm_guest.config
      else
         echo "Generate a kernel .config before continuing"
         echo "Recommended:"
         echo -e "\t${MAKE} defconfig"
         echo -e "\t${MAKE} kvm_guest.config"
         exit 1
      fi
   fi

   cp "$KCONFIG" "$KCONFIG_CONFIG"

   # Merge all required config values for tc testing
   KCONFIG_CONFIG="$KCONFIG_CONFIG" \
      bash -c "$KDIR/scripts/kconfig/merge_config.sh -m $KCONFIG_CONFIG $WD/config > /dev/null"

   # We need all modules to be built as "built-in"
   ${MAKE} KCONFIG_CONFIG="$KCONFIG_CONFIG" mod2yesconfig

   ${MAKE} KCONFIG_CONFIG="$KCONFIG_CONFIG" bzImage

   if ! [ -f "$KIMG" ]; then
      echo "Kernel image not found. Build failed?"
      exit 1
   fi
}

# Default architecture
ARCH="x86_64"
CROSS="n"

# Known directories and files
WD=$(dirname -- "$(realpath "$0")")
KDIR=$(realpath "$WD/../../../../")
KCONFIG="$KDIR/.config"
ROOTFS="/"

# VM Settings
VMCPUS=$(nproc)
VMMEM=512M

# Default command if none is given
DEFAULT_CMD="./tdc.py"

JOBS=$(nproc)

# Our internal kernel configuration file
KCONFIG_CONFIG="$WD/.tdc-config"

if ! [ -x "$(command -v virtme-run)" ]; then
   echo "virtme is not installed and is required."
   exit 1
fi

while getopts 'ha:r:i:c:m:j:f:sgd' OPT; do
   case "$OPT" in
      h)
         help
         exit 0
         ;;
      a)
         ARCH="$OPTARG"
         ;;
      r)
         ROOTFS=$(realpath "$OPTARG")
         ;;
      i)
         _KIMG="$OPTARG"
         if ! [ -f "$_KIMG" ]; then
            echo "$_KIMG doesn't exist"
            exit 1
         fi
         ;;
      c)
         VMCPUS="$OPTARG"
         ;;
      m)
         VMMEM="$OPTARG"
         ;;
      j)
         JOBS="$OPTARG"
         ;;
      f)
         KCONFIG=$(realpath "$OPTARG")
         if ! [ -f "$KCONFIG" ]; then
            echo "Configuration file $KCONFIG doesn't exist"
            exit 1
         fi
         ;;
      s)
         VMSHELL="y"
         ;;
      g)
         KCONFIG_GEN="y"
         ;;
      d)
         DRYRUN="y"
         ;;
      \? )
         help
         exit 1
         ;;
   esac
done
shift $((OPTIND -1))

if [[ $# -eq 0 ]]; then
   if ! [ "$VMSHELL" == "y" ]; then
      echo "No command specified. Running $DEFAULT_CMD".
      CMD="$DEFAULT_CMD"
   fi
else
   CMD="$@"
fi


# Check if we are cross-compiling
verify_arch "$ARCH"
if ! uname -m | grep -q "$LINUX_ARCH"; then
   echo ">>> Cross architecture detected <<<"
   CROSS="y"
fi

if [ -z "$_KIMG" ]; then
   KIMG="$KDIR"/arch/"$LINUX_ARCH"/boot/bzImage
   if ! [ "$DRYRUN" == "y" ]; then
      recrec
   fi
else
   KIMG="$_KIMG"
fi

if [ "$DRYRUN" == "y" ]; then
   virtme-run \
      --arch "$QEMU_ARCH" \
      --root "$ROOTFS" \
      --kimg "$KIMG" \
      --cpus "$VMCPUS" \
      --memory "$VMMEM" \
      --rwdir="/mnt=$KDIR" \
      --dry-run \
      --show-command
   exit 0
fi

if [ "$VMSHELL" == "y" ]; then
   virtme-run \
      --arch "$QEMU_ARCH" \
      --root "$ROOTFS" \
      --kimg "$KIMG" \
      --cpus "$VMCPUS" \
      --memory "$VMMEM" \
      --rwdir="/mnt=$KDIR"
else
   virtme-run \
      --arch "$QEMU_ARCH" \
      --root "$ROOTFS" \
      --kimg "$KIMG" \
      --cpus "$VMCPUS" \
      --memory "$VMMEM" \
      --show-boot-console \
      --rwdir="/mnt=$KDIR" \
      --script-sh "cd /mnt/tools/testing/selftests/tc-testing && $CMD" < /dev/zero
fi
