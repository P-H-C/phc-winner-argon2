#! /usr/bin/env bash

_exit_code=0

for file in $(ls | grep '^[a-z2]*\(_v\)\?[0-9]*$' | xargs); do
    new=$(shasum -a 256 "${file}")
    old=$(cat "${file}.shasum")
    if [ "${new}" = "${old}" ]; then
        echo -e "${file} \t OK"
    else
        echo -e "${file} \t ERROR: checksum mismatch"
        _exit_code=1
    fi
done

exit ${_exit_code}
