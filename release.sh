#!/bin/bash
#
JOBS=`grep -c processor /proc/cpuinfo`
let JOBS=${JOBS}*2
JOBS="-j${JOBS}"
RELEASE_DATE=`date +%Y%m%d`
COMMIT_ID=`git log --pretty=format:'%h' -n 1`
BOOT_PATH="arch/arm/boot"
DZIMAGE="dzImage"
MODEL=${1}
IMG_NAME=${2}
TIZEN_MODEL=tizen_${MODEL}

if [ "${MODEL}" = "" ]; then
	echo "Warnning: failed to get machine id."
	echo "ex)./release.sh model_name"
	echo "ex)--------------------------------------------------"
	echo "ex)./release.sh	tm1"
	exit
fi

if [ ${MODEL} = "coreprimeve3g" -o ${MODEL} = "tm1" ]; then
	MODULE=1
else
	MODULE=0
fi

make ARCH=arm ${TIZEN_MODEL}_defconfig
if [ "$?" != "0" ]; then
	echo "Failed to make defconfig :"$ARCH
	exit 1
fi

make ${JOBS} zImage ARCH=arm
if [ "$?" != "0" ]; then
	echo "Failed to make zImage"
	exit 1
fi

DTC_PATH="scripts/dtc/"

rm ${BOOT_PATH}/dts/*.dtb -f

make ARCH=arm dtbs
if [ "$?" != "0" ]; then
	echo "Failed to make dtbs"
	exit 1
fi

./scripts/sprd_dtbtool.sh -p ${DTC_PATH} -v ${BOOT_PATH}/dts/
if [ "$?" != "0" ]; then
	echo "Failed to make merged-dtb"
	exit 1
fi

./scripts/sprd_mkdzimage.sh
if [ "$?" != "0" ]; then
	echo "Failed to make mkdzImage"
	exit 1
fi

if [ ${MODULE} -eq 1 ]; then
	sudo ls > /dev/null
	./scripts/mkmodimg.sh
fi

if [ "${IMG_NAME}" != "" ]; then
	RELEASE_IMAGE=System_${MODEL}_${RELEASE_DATE}_${IMG_NAME}.tar
else
	RELEASE_IMAGE=System_${MODEL}_${RELEASE_DATE}-${COMMIT_ID}.tar
fi

tar cf ${RELEASE_IMAGE} -C ${BOOT_PATH} ${DZIMAGE}
if [ "$?" != "0" ]; then
	echo "Failed to tar ${DZIMAGE}"
	exit 1
fi

if [ ${MODULE} -eq 1 ]; then
	tar rf ${RELEASE_IMAGE} -C usr/tmp-mod modules.img
	if [ "$?" != "0" ]; then
		echo "Failed to tar modules.img"
		exit 1
	fi
fi

echo ${RELEASE_IMAGE}
