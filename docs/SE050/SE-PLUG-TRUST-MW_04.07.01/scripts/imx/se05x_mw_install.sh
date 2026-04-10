#!/bin/bash
# Copyright 2019,2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Pass zipped MW as argument to script.
# Filename of zip archive is supposed to as:
#
# se050_mw_v[NN].[NN].[NN].zip
#
# For example: se050_mw_v02.07.00.zip

#
# 2019-08-28 Updated for v02.11.00
# - python3 instead of python available on i.MX platform
#
# 2019-07-24 Updated for v02.10.00
# - Zip archive now has additional 'simw_top' toplevel directory
#

# Global variables
# ----------------
root_dir="/home/root"

# UTILITY FUNCTIONS
# -----------------
# execCommand will stop script execution when the program executed did not return OK (i.e. 0) to the shell
execCommand () {
    local command="$*"
    echo ">> ${command}"
    ${command}
    local nRetProc="$?"
    if [ ${nRetProc} -ne 0 ]
    then
        echo "\"${command}\" failed to run successfully, returned ${nRetProc}"
        exit 2
    fi
    echo ""
}

dummyCommand () {
    local command="$*"
    echo ">> ${command}"
    # ${command}
    local nRetProc="$?"
    if [ ${nRetProc} -ne 0 ]
    then
        echo "\"${command}\" failed to run successfully, returned ${nRetProc}"
        exit 2
    fi
    echo ""
}

if [ -z "$1" ]; then
    echo "Please provide zip archive containing MW as argument"
    exit 2
else
    mw_package="$1"
fi

# Cd to directory where script is stored
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo ${SCRIPT_DIR}
cd ${SCRIPT_DIR}

echo "Installing ${mw_package}"
mw_dir_name=${mw_package%.*} # Back delete
mw_build_area_dir_name="${mw_dir_name}/simw-top_build"

# This script is being modified so it is no longer tied to a specific revision.
# The initial version only worked for 02.07.00

mw_name=${mw_package%.zip} # strip .zip extension
mw_version=${mw_name#*_mw_} # only keep vNN.NN.NN
echo ${mw_version}
# Check on version (filename based) and only use with version 02.07.00
# if [ "${mw_version}" != "v02.07.00" ]; then
    # echo "This MW installation script contains patches specific to version v02.07.00"
    # echo "It cannot be used to install ${mw_package} (version=${mw_version})"
    # echo "Error: Failed to install package ${mw_package}"
    # exit 4
# fi

# Check for unlikely date (in case NTP server is not reacheable date defaults to build date of Yocto image)

atLeastDate=$(date -d 2020-08-07 +%s)
currentDate=$(date +%s)

if [ ${currentDate} -le ${atLeastDate} ]; then
    echo "System date is not correct:"
    date
    echo "You can manually set the date like"
    echo "   date -s '2020-08-07 14:20'"
    echo "and then rerun the script"
    echo ""
    echo "Note: a wrong system date may cause compilation and installation issues"
    exit 5
fi


# Ensure target directory does not yet exist
if [ -d "${root_dir}/${mw_dir_name}" ]; then
    echo "Installation error: ${root_dir}/${mw_dir_name} already exists"
    echo "Error: Failed to install package ${mw_package}"
    exit 3
fi

# Ensure build directory does not yet exist
if [ -d "${root_dir}/${mw_build_area_dir_name}" ]; then
    echo "Installation error: ${root_dir}/${mw_build_area_dir_name} already exists"
    echo "Error: Failed to install package ${mw_package}"
    exit 3
fi

execCommand "mkdir -p ${root_dir}/mnt"
execCommand "mkdir ${root_dir}/${mw_dir_name}"
execCommand "cp ${mw_package} ${root_dir}/${mw_dir_name}"
execCommand "cd ${root_dir}/${mw_dir_name}"
execCommand "unzip ${mw_package}"
execCommand "cd ${root_dir}/${mw_dir_name}/simw-top"
execCommand "python3 scripts/create_cmake_projects.py"
execCommand "rm ${root_dir}/${mw_dir_name}/${mw_package}"

execCommand "cd ${root_dir}/${mw_build_area_dir_name}/imx_native_se050_t1oi2c"
execCommand "cmake -L ."
execCommand "cmake -DSE05X_Auth:STRING=None ."  # >= 02.07.00 specific (deviate when sample contains credentials)
execCommand "cmake $2 ."  # >= 02.07.00 specific (deviate when sample contains credentials)

execCommand "cmake --build ."
execCommand "make install"
execCommand "ldconfig /usr/local/lib"

execCommand "cd ${root_dir}/${mw_dir_name}/simw-top"
find . -name "*.sh" -exec chmod 755 {} \;
execCommand "cd pycli/src"
execCommand "python3 setup.py develop"

# Compile TLS client
execCommand "cd ${root_dir}/${mw_dir_name}/simw-top/demos/linux/tls_client/build"
execCommand "cmake ../."
execCommand "cmake --build ."

# #########################################
# Verification (In case SE050 is connected)
# cd ../../sss/plugin/openssl/scripts
# python3 openssl_provisionEC.py prime192v1 t1oi2c none
# python3 openssl_EccSign.py prime192v1
