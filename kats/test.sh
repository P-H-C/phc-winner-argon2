#!/bin/sh

make genkat > /dev/null
if [ $? -ne 0 ]
then
  exit $?
fi

printf "argon2i "
./genkat i > tmp
if diff tmp kats/argon2i
then
  printf "OK"
else
  printf "ERROR"
  exit 1
fi
printf "\n"

printf "argon2d "
./genkat d > tmp
if diff tmp kats/argon2d
then
  printf "OK"
else
  printf "ERROR"
  exit 2
fi
printf "\n"

make genkat OPTTEST=1 > /dev/null
if [ $? -ne 0 ]
then
  exit $?
fi

printf "argon2i "
./genkat i > tmp
if diff tmp kats/argon2i
then
  printf "OK"
else
  printf "ERROR"
  exit 3
fi
printf "\n"

printf "argon2d "
./genkat d > tmp
if diff tmp kats/argon2d
then
  printf "OK"
else
  printf "ERROR"
  exit 4
fi
printf "\n"

rm -f tmp

exit 0
