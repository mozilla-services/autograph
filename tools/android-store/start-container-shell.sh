#!/usr/bin/env bash

USAGE="usage: ${0##*/}
Start shell in autograph container for android store operations

Options:
    -h|--help	    output this help
"

set -eu

warn() { for m; do echo "$m"; done 1>&2 ; }
die() { warn "$@" ; exit 2; }
usage() { warn "$@" "${USAGE:-}" ; [[ $# == 0 ]] && exit 0 || exit 1;}

# where the ramdisk might be on the host computer
RAM_DISK=${RAM_DISK:-/tmp/ramdisk}

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
	-h|--help) usage ;;
	-*) usage "Unknown option '$1'" ;;
	*) break ;;
    esac
    shift
done

# Now have non-option args
test $# -eq 0 || usage "Wrong # args"

# set up an alias for make
prog_dir=$(cd $(dirname "$0"); /bin/pwd)
makefile="${prog_dir}/Makefile"
test -r "$makefile" || die "Can't find Makefile at ${makefile}"
export makefile

function make() {
    command make --makefile="${makefile}" "$@"
}
export -f make
# and add completion for targets to our ~/.bashrc to make life easier
cat >>~/.bashrc <<EOF
complete -W "\`grep -oE '^[a-zA-Z0-9_-]+:([^=]|$)' "${makefile}" | sed 's/[^a-zA-Z0-9_-]*$//'\`" make
EOF

# and put that dir on the path
export PATH="${prog_dir}":$PATH

# get to the working directory
if test -d "${RAM_DISK}"; then
    warn "Not running in container -- assuming you're testing!"
else
    RAM_DISK=/secrets
fi
cd "${RAM_DISK}/t"

# and give the user a shell
bash -i
