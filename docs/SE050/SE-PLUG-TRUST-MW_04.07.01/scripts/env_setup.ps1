# Copyright 2022 NXP
# SPDX-License-Identifier: Apache-2.0

$MCUX_DIR= "NO_MCUXPRESSO"
#latest version at the end, oldest version at top.
#set path for MCUX_DIR
$path= 'C:\nxp\MCUXpressoIDE_10.0.2_411'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_10.2.0_759'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_10.2.1_795'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_10.3.0_2200'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_10.3.1_2233'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_11.0.0_2516'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_11.0.1_2563'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_11.1.0_3209'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_11.1.1_3241'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_11.2.0_4120'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_11.2.1_4149'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_11.3.0_5222'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_11.3.1_5262'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_11.4.0_6237'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_11.4.1_6260'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}
$path= 'C:\nxp\MCUXpressoIDE_11.5.0_7232'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}

$path= 'C:\nxp\MCUXpressoIDE_11.5.1_7266'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}

$path= 'C:\nxp\MCUXpressoIDE_11.6.1_8255'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}

$path= 'C:\nxp\MCUXpressoIDE_11.7.1_9221'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}

$path= 'C:\nxp\MCUXpressoIDE_11.8.0_1165'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}

$path= 'C:\nxp\MCUXpressoIDE_11.9.1_2170'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}

$path= 'C:\nxp\MCUXpressoIDE_24.12.148'
if (Test-Path -Path $path)
{
	$MCUX_DIR= $path
}

if($MCUX_DIR -ne 'NO_MCUXPRESSO')
{
	Write-Output "# INFO: Using MCUXPresso from '$MCUX_DIR' for Kinetis/LPC/iMX.RT Controllers."
}
else
{
	Write-Output "!! WARNING !! MCUXPresso was not found."
	Write-Output "!! WARNING !! You may have to update %~0 to compile for Kinties/LPC/iMXRT controllers."
}


function CMAKE_SET{
	$Env:ARMGCC_DIR="$MCUX_DIR\ide\tools"
	$ARMGCC_DIR="$MCUX_DIR\ide\tools"
	$Env:PATH = "C:\MinGW\bin;C:\MinGW\msys\1.0\bin\make.exe;C:\MinGW\mingw32\bin;$PYTHON_DIR;$PYTHON_DIR\scripts;$CMAKE_DIR;$MCUX_DIR\ide\tools\bin;$MCUX_DIR\ide\buildtools\bin;$Env:PATH"

	$SE050_ENV_IS_SETUP=1

}


function PYTHON_SET{
	$CMAKE_DIR="NO_CMAKE"
	$path='C:\Program Files\CMake\bin'
	if(Test-Path -path $path){
		$CMAKE_DIR=$path
		&CMAKE_SET
	}
	$path='C:\opt\cmake\bin'
	if(Test-Path -path $path){
		$CMAKE_DIR=$path
		&CMAKE_SET
	}
	if($CMAKE_DIR -ne 'NO_CMAKE'){
		Write-Output "# INFO: Using CMake from '$CMAKE_DIR'"
	}
	#Without CMake, only the MCUXPresso projects would work.
	else{
		Write-Output "!WARNING! CMake not autodetected."
        Write-Output "!WARNING! You may have to update %~0 to add extend detection of CMake."
	}

}

function MSVC_SET{
	$JAVA_HOME="JAVA_NOT_INSTALLED"
	$path='C:\Program Files\Java\jdk1.8.0_191\bin\java.exe'
	if (Test-Path -Path $path){
		$JAVA_HOME=$Path
	}
	$path='C:\Program Files\Java\jdk1.8.0_201\bin\java.exe'
	if (Test-Path -Path $path){
		$JAVA_HOME=$Path
	}
	$path='C:\Program Files\Java\jdk1.8.0_211\bin\java.exe'
	if (Test-Path -Path $path){
		$JAVA_HOME=$Path
	}
	$path='C:\Program Files\Java\jdk1.8.0_291\bin\java.exe'
	if (Test-Path -Path $path){
		$JAVA_HOME=$Path
	}
	$PYTHON_DIR="NO_Python"
	$path="$env:LOCALAPPDATA\Programs\Python\Python39-32\python.exe"
	if(Test-Path -path $path){
		$PYTHON_DIR=$path
		&PYTHON_SET
	}
	$path="$env:LOCALAPPDATA\Programs\Python\Python38-32\python.exe"
	if(Test-Path -path $path){
		$PYTHON_DIR=$path
		&PYTHON_SET
	}
	$path="$env:LOCALAPPDATA\Programs\Python\Python37-32\python.exe"
	if(Test-Path -path $path){
		$PYTHON_DIR=$path
		&PYTHON_SET
	}
	$path='C:\Python39-32\python.exe'
	if(Test-Path -path $path){
		$PYTHON_DIR=$path
		&PYTHON_SET
	}
	$path='C:\Python38-32\python.exe'
	if(Test-Path -path $path){
		$PYTHON_DIR=$path
		&PYTHON_SET
	}
	$path='C:\Python37-32\python.exe'
	if(Test-Path -path $path){
		$PYTHON_DIR=$path
		&PYTHON_SET
	}
	$path='C:\Python39\python.exe'
	if(Test-Path -path $path){
		$PYTHON_DIR=$path
		&PYTHON_SET
	}
	$path='C:\Python38\python.exe'
	if(Test-Path -path $path){
		$PYTHON_DIR=$path
		&PYTHON_SET
	}
	$path='C:\Python37\python.exe'
	if(Test-Path -path $path){
		$PYTHON_DIR=$path
		&PYTHON_SET
	}
	if($PYTHON_DIR -ne 'NO_Python' ){
		Write-Output "# INFO: Using Python from '$PYTHON_DIR'"
	}
	else{
		Write-Output "!WARNING! Python 3 32bit not detected.  Python scripts and ssscli Tool may not work."
        Write-Output "!WARNING! You may have to update to add extend detection of Python 3 32bit."
	}


}

#Default is visual studio 2015 if available.
#For other visual studio release, we select latest version first and then older versions


$MSVC_DIR="NO-DIR"
$path="$env:VS140COMNTOOLS\vsvars32.bat"
If (Test-Path -Path $path) {
	    $MSVC_DIR=$path
		&MSVC_SET
}
$path='C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat'
If (Test-Path -Path $path) {
	    $MSVC_DIR=$path
		&MSVC_SET
}

$path='C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat'
If (Test-Path -Path $path) {
	    $MSVC_DIR=$path
		&MSVC_SET
}
$path='C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat'
If (Test-Path -Path $path) {
	    $MSVC_DIR=$path
		&MSVC_SET
}
$path='C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat'
If (Test-Path -Path $path) {
	    $MSVC_DIR=$path
		&MSVC_SET
}

$path='C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat'
If (Test-Path -Path $path) {
	    $MSVC_DIR=$path
		&MSVC_SET
}
$path='C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat'
If (Test-Path -Path $path) {
	    $MSVC_DIR=$path
		&MSVC_SET
}
$path='C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars32.bat'
If (Test-Path -Path $path) {
	    $MSVC_DIR=$path
		&MSVC_SET
}
$path='C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat'
If (Test-Path -Path $path) {
	    $MSVC_DIR=$path
		&MSVC_SET
}
$path='C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat'
If (Test-Path -Path $path) {
	    $MSVC_DIR=$path
		&MSVC_SET
}
$path='C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvars32.bat'
If (Test-Path -Path $path) {
	    $MSVC_DIR=$path
		&MSVC_SET
}

$path='C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars32.bat'
If (Test-Path -Path $path) {
	    $MSVC_DIR=$path
		&MSVC_SET
}
$path='C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\Tools\VsDevCmd.bat'
If (Test-Path -Path $path) {
	    $MSVC_DIR=$path
		&MSVC_SET
}
if($MSVC_DIR_DIR -ne 'NO-DIR')
{
	Write-Output "# INFO: Using MSVC from '$MSVC_DIR'  ."
}
else
{
	Write-Output '!! WARNING!!  Visual Studio not found/autodetected.'
    Write-Output '!! WARNING!!  You may have to update  to compile for Visual Studio.'
}














