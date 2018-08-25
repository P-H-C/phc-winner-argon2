#!/usr/bin/env bash

set -o errexit
set -o pipefail

export PS4="+${BASH_SOURCE[0]}:${LINENO}:${FUNCNAME}: "
#set -o xtrace

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__file="${__dir}/$(basename "${BASH_SOURCE[0]}")"
__base="$(basename ${__file} .bash)"

function __usage ()
{
	cat <<-USAGE_HELP
	Usage: ${__base} [flags]

	Options:
	    --genkat: Location of genkat binary
	    -h,--help: Display this help
	    -v,--verbose: Verbose output
USAGE_HELP
}

function __parse_args() {
	if [[ $# -eq 0 ]]; then
		__usage
		exit 1
	fi

	while true; do
		case ${1} in
			-h|-\?|--help)
				__usage
				exit 0
				;;
			--genkat)
				if [ -n "$2" ]; then
					_genkat=$2
					shift
				else
					printf 'ERROR: "--genkat" requires a non-empty option argument.\n' >&2
					exit 1
				fi
				;;
			--genkat=?*)
				_genkat=${1#*=} # Delete everything up to "=" and assign the remainder.
				;;
			--genkat=)       # Handle the case of an empty --genkat=
				printf 'ERROR: "--genkat" requires a non-empty option argument.\n' >&2
				exit 1
				;;
			-v|--verbose)
				_verbose=$((verbose + 1)) # Each -v argument adds 1 to verbosity.
				;;
			--)              # End of all options.
				shift
				break
				;;
			-?*)
				printf 'WARN: Unknown option (ignored): %s\n' "$1" >&2
				;;
			*)               # Default case: If no more options then break out of the loop.
				break
		esac

		shift
	done

	if [[ -z ${_genkat+1} ]]; then
		__usage
		exit 1
	fi
    if [[ ! -f ${_genkat} ]]; then
        printf "ERROR: ${_genkat} does not exist.\n" >&2
        exit 2
    fi
}

function __main () {

	__parse_args $@

    # create temporary directory
    local tmpdir=$(mktemp -d "${TMPDIR:-/tmp/}genkat.XXXXXXXXXXXX")
    mkdir -p ${tmpdir}

    i=0
    for version in 16 19; do
        for type in i d id; do
            i=$(($i+1))

            printf "argon2$type  \tv=$version: \t"

            if [ 19 -eq $version ]; then
                kats="argon2"$type
            else
                kats="argon2"$type"_v"$version
            fi

            ${_genkat} $type $version > "${tmpdir}/${kats}"
            if diff --strip-trailing-cr "${tmpdir}/${kats}" "${__dir}/$kats"; then
                printf "OK"
            else
                printf "ERROR"
                exit $i
            fi
            printf "\n"
        done
    done

	rm -rf ${tmpdir}

	exit 0
}

__main $@
