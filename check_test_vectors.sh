#!/bin/bash
#
# Argon2 source code package
# 
# This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
# 
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
#


# Get current script path
script_path=$(dirname $0)


# Change current directory to root directory
if [ '.' != $script_path ] ; then
	cd $script_path/../
fi


ARGON2_TYPES=(Argon2d Argon2i Argon2id Argon2ds)
ARGON2_IMPLEMENTATIONS=(REF OPT)

TEST_PATH=./test/

KAT_REF=kat-argon2-ref.log
KAT_OPT=kat-argon2-opt.log


# Parse script arguments
for i in "$@"
do
	case $i in
		-s=*|-src=*|--source=*)
			SOURCE_DIR="${i#*=}"
			shift
			;;
		*)
			# Unknown option
			;;
	esac
done


# Change current directory to source directory
cd $SOURCE_DIR


for implementation in ${ARGON2_IMPLEMENTATIONS[@]}
do
	echo "Test for $implementation"

	make_log=$TEST_PATH"make_"$implementation".log"
	rm -f $make_log

	flags=""
	if [ "OPT" == "$implementation" ] ; then
		flags="OPT=TRUE"
	fi

	make $flags &> $make_log

	if [ 0 -ne $? ] ; then
		echo -e "\t\t -> Wrong! Make error! See $make_log for details!"
		continue
	else
		rm -f $make_log
	fi


	for type in ${ARGON2_TYPES[@]}
	do
		echo -e "\t Test for $type"

		kat_file_name="KAT_"$implementation
		kat_file=${!kat_file_name}
		rm -f $kat_file

		run_log=$TEST_PATH"run_"$type"_"$implementation".log"
		./../../Build/argon2-tv -gen-tv -type $type > $run_log
		if [ 0 -ne $? ] ; then
			echo -e "\t\t -> Wrong! Run error! See $run_log for details!"
			continue
		else
			rm -f $run_log
		fi


		kat_file_copy=$TEST_PATH/${kat_file/"argon2"/$type}
		cp $kat_file $kat_file_copy
		rm -f $kat_file

		test_vectors_file=$TEST_PATH$type".txt"

		diff_file=$TEST_PATH"diff_"$type"_"$implementation
		rm -f $diff_file


		if diff -Naur $kat_file_copy $test_vectors_file > $diff_file ; then
			echo -e "\t\t -> OK!"
			rm -f $kat_file_copy
			rm -f $diff_file
		else
			echo -e "\t\t -> Wrong! See $diff_file for details!"
		fi
	done
done
