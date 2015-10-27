#!/bin/sh

make genkat
if [ $? -ne 0 ]
then
  exit $?
fi

printf "argon2i "
./genkat i > tmp
if diff tmp kats/argon2i
then printf "ok"
else printf "error"
fi
printf "\n"

printf "argon2d "
./genkat d > tmp
if diff tmp kats/argon2d
then printf "ok"
else printf "erro"
fi
printf "\n"

make genkat OPT=TRUE
if [ $? -ne 0 ]
then
  exit $?
fi

printf "argon2i "
./genkat i > tmp
if diff tmp kats/argon2i
then printf "ok"
else printf "error"
fi
printf "\n"

printf "argon2d "
./genkat d > tmp
if diff tmp kats/argon2d
then printf "ok"
else printf "error"
fi
printf "\n"

rm -f tmp
