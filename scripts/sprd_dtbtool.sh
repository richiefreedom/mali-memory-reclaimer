#!/bin/bash


## Functions
function write_to_4bytes_binary()
{
	HEX=`echo "obase=16; $1" | bc`

	NUM=$((8-${#HEX}))

	ZERO="00000000"
	SUB=${ZERO:0:$NUM}

	HEX=$SUB$HEX

	for str in $(echo $HEX | sed 's/../& /g' | rev); do
		str=$(echo -en $str | rev)
		echo -en "\x$str"
	done > $2
}

function write_to_padding_binary()
{
	rm -f padding

	PAD_SIZE=$(($(($PAD - $(($1 % $PAD)))) % $PAD))
	if [ $PAD_SIZE -gt 0 ]; then
		dd if=/dev/zero of=./padding bs=1 count=$PAD_SIZE 2>/dev/zero
	else
		touch padding
	fi

	echo -en " | PAD: $PAD_SIZE[B]\n"
}

function get_dtb_size()
{
	SIZE=`du -b $1 | awk '{print $1}'`
	PAD_SIZE=$(($(($PAD - $(($SIZE % $PAD)))) % $PAD))
	DTB_SIZE=$(($SIZE + $PAD_SIZE))
}


## Defines
OUT="merged-dtb"
OUT_TMP="multi.tmp"

OUT_DIR="./arch/arm/boot"
DTS_DIR="./arch/arm/boot/dts"

SPRD_MAGIC="SPRD"
SPRD_VERSION=1

DTB=(
"sprd-scx35-tizen_z3-r00.dtb"
"sprd-scx35-tizen_z3-r01.dtb"
"sprd-scx35-tizen_z3-r02.dtb"
"sprd-scx35-tizen_z3-r03.dtb"
)
DTB_CNT=4

CHIPSET=8830
PLATFORM=0
REV=131072
DTB_OFFSET=2048

ENDOFHEADER=0

PAD=2048


## Header
rm -f $OUT
rm -f $OUT_TMP
touch $OUT_TMP

HEADER_SIZE=$((12 + 20 * $DTB_CNT + 4))

echo -en " *HEADER "
echo -en "$HEADER_SIZE[B]\n"

echo -en $SPRD_MAGIC > $OUT
cat $OUT >> $OUT_TMP
write_to_4bytes_binary $SPRD_VERSION $OUT
cat $OUT >> $OUT_TMP
write_to_4bytes_binary $DTB_CNT $OUT
cat $OUT >> $OUT_TMP

for i in ${DTB[*]}; do
	FILE="$DTS_DIR/$i"
	if [ -e $FILE ]; then
		write_to_4bytes_binary $CHIPSET $OUT
		cat $OUT >> $OUT_TMP

		write_to_4bytes_binary $PLATFORM $OUT
		cat $OUT >> $OUT_TMP
		PLATFORM=$(($PLATFORM + 1))

		write_to_4bytes_binary $REV $OUT
		cat $OUT >> $OUT_TMP

		write_to_4bytes_binary $DTB_OFFSET $OUT
		cat $OUT >> $OUT_TMP

		get_dtb_size $FILE
		write_to_4bytes_binary $DTB_SIZE $OUT
		cat $OUT >> $OUT_TMP

		DTB_OFFSET=$(($DTB_OFFSET + $DTB_SIZE))
	else
		echo -en "$i not found.\nexit\n"
		exit -1
	fi
done

write_to_4bytes_binary $ENDOFHEADER $OUT
cat $OUT >> $OUT_TMP

write_to_padding_binary $HEADER_SIZE
cat $OUT_TMP padding > $OUT


## DTB
for i in ${DTB[*]}; do
	FILE="$DTS_DIR/$i"
	if [ -e $FILE ]; then
		NAME=`echo $i`
		echo -en " *$NAME "

		cat $OUT $FILE > $OUT_TMP

		SIZE=`du -b $FILE | awk '{print $1}'`
		echo -en "$SIZE[B]\n"

		write_to_padding_binary $SIZE
		cat $OUT_TMP padding > $OUT
	else
		echo -en "$i not found.\nexit\n"
		exit -1
	fi
done


## End
rm -f $OUT_TMP
rm -f padding
rm -f $OUT_DIR/$OUT
mv -f $OUT $OUT_DIR/

S=`du -b $OUT_DIR/$OUT | awk '{print $1}'`
S_K=$(($S/1024))
echo -en "## OUT: $OUT size: $S[B]; $S_K[K]\n"
