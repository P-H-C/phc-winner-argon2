#!/bin/bash

#
# Argon2 source code package
# 
# This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
# 
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
#

TYPES=(d i)
IMPLEMENTATIONS=(REF OPT)

TESTS_PATH=./tests/

KAT_REF=kat-argon2-ref.log
KAT_OPT=kat-argon2-opt.log


# Default arguments

for implementation in ${IMPLEMENTATIONS[@]}
do
	echo "$implementation implementation"

	make_log=$TESTS_PATH"make_"$implementation".log"
	rm -f $make_log

	flags=""
	if [ "OPT" == "$implementation" ] ; then
		flags="OPT=TRUE"
	fi

	make $flags &> $make_log

	if [ 0 -ne $? ] ; then
		echo -e "\tFAIL: make error, see $make_log"
		continue
	else
		rm -f $make_log
	fi


	for type in ${TYPES[@]}
	do
		echo -n -e "argon2$type"

		kat_file_name="KAT_"$implementation
		kat_file=${!kat_file_name}
		rm -f $kat_file

		run_log=$TESTS_PATH"run_"$type"_"$implementation".log"
		./argon2 g --type $type > $run_log
		if [ 0 -ne $? ] ; then
			echo -e "\tFAIL: run error, see $run_log"
			continue
		else
			rm -f $run_log
		fi

		kat_file_copy=$TESTS_PATH/${kat_file/"argon2"/$type}
		cp $kat_file $kat_file_copy
		rm -f $kat_file

		test_vectors_file=$TESTS_PATH"argon2"$type

		diff_file=$TESTS_PATH"diff_"$type"_"$implementation
		rm -f $diff_file

		if diff -Naur $kat_file_copy $test_vectors_file > $diff_file ; then
			echo -e " \t\tOK"
			rm -f $kat_file_copy
			rm -f $diff_file
		else
			echo -e "\t\tFAIL: wrong values, see $diff_file"
		fi
	done
done
