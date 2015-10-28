#!/bin/sh

make genkat > /dev/null
if [ $? -ne 0 ]
then
  exit $?
fi

printf "argon2i "
./genkat i > tmp
if diff tmp kats/argon2i
then printf "OK"
else printf "ERROR"
fi
printf "\n"

printf "argon2d "
./genkat d > tmp
if diff tmp kats/argon2d
then printf "OK"
else printf "ERROR"
fi
printf "\n"

make genkat OPT=TRUE > /dev/null
if [ $? -ne 0 ]
then
  exit $?
fi

printf "argon2i "
./genkat i > tmp
if diff tmp kats/argon2i
then printf "OK"
else printf "ERROR"
fi
printf "\n"

printf "argon2d "
./genkat d > tmp
if diff tmp kats/argon2d
then printf "OK"
else printf "ERROR"
fi
printf "\n"

rm -f tmp
