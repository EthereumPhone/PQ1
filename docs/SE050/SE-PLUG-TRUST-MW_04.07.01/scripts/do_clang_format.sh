#!/bin/bash

# Copyright 2018,2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    # Checkout as-is commit LF
    git config --global core.autocrlf input
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # Mac OSX
    # Checkout as-is commit LF
    git config --global core.autocrlf input
fi

# No warning for CRLF to LF
git config --global core.safecrlf false

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

CLANG_FORMAT_FIND="find"
CMAKE_FORMAT_PREFIX="echo "
CMAKE_FORMAT_FIND="${CMAKE_FORMAT_PREFIX} find"
CMAKE_FORMAT_GIT="${CMAKE_FORMAT_PREFIX} git"
CMAKE_FORMAT_PYTHON="${CMAKE_FORMAT_PREFIX} python"

#echo SCRIPTPATH=${SCRIPTPATH}
cd ${SCRIPTPATH}/..

for d in sss doc/input hostlib/useCase akm demos/se05x demos/a71ch semslite/lib
do
    ${CLANG_FORMAT_FIND} $d -type f -name "*.h" -print -exec clang-format -i "{}" ";"
    ${CLANG_FORMAT_FIND} $d -type f -name "*.c" -print -exec clang-format -i "{}" ";"
    ${CLANG_FORMAT_FIND} $d -type f -name "*.cpp" -print -exec clang-format -i "{}" ";"
    ${CLANG_FORMAT_FIND} $d -type f -name "*.hpp" -print -exec clang-format -i "{}" ";"
    ${CLANG_FORMAT_FIND} $d -type f -name "*.c.txt" -print -exec clang-format -i "{}" ";"
done


for d in demos sss tst doc/input hostlib hostlib/hostLib/se05x hostlib/hostLib/se05x_03_xx_xx akm scripts
do
    ${CMAKE_FORMAT_FIND} $d -type f -name "CM*.txt" -print -exec cmake-format -i "{}" -c ${SCRIPTPATH}/cmake-format.json ";"
    ${CMAKE_FORMAT_FIND} $d -type f -name "*.cmake" -print -exec cmake-format -i "{}" -c ${SCRIPTPATH}/cmake-format.json ";"
done

cd ${SCRIPTPATH}

${CMAKE_FORMAT_GIT} checkout -- CodeCoverage.cmake
${CMAKE_FORMAT_GIT} checkout -- ToolchainFile_imx6.cmake
${CMAKE_FORMAT_GIT} checkout -- cmake_options.cmake

${CMAKE_FORMAT_PYTHON} cmake_options.py
