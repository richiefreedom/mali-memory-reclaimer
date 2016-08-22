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


## Defines
OUT="dzImage"
OUT_TMP="dzImage.tmp"

OUT_DIR="./arch/arm/boot"
BOOT_DIR="./arch/arm/boot"

MAGIC="NZIT"		# 0x54495A4E
KERNEL_ADDR=32768	# 0x00008000
ATAGS_ADDR=31457280	# 0x01e00000

PAD=2048


## Header
rm -f $OUT
rm -f $OUT_TMP
touch $OUT_TMP

HEADER_SIZE=28

echo -en " *HEADER "
echo -en "$HEADER_SIZE[B]\n"

echo -en $MAGIC > $OUT
cat $OUT >> $OUT_TMP
write_to_4bytes_binary $KERNEL_ADDR $OUT
cat $OUT >> $OUT_TMP

FILE="$BOOT_DIR/zImage"
if [ -e $FILE ]; then
	SIZE=`du -b $FILE | awk '{print $1}'`
	write_to_4bytes_binary $SIZE $OUT
	cat $OUT >> $OUT_TMP
else
	echo -en "$FILE not found.\nexit\n"
	exit -1
fi

DTB_ADDR=$(($KERNEL_ADDR + $SIZE))
write_to_4bytes_binary $DTB_ADDR $OUT
cat $OUT >> $OUT_TMP

FILE="$BOOT_DIR/merged-dtb"
if [ -e $FILE ]; then
	SIZE=`du -b $FILE | awk '{print $1}'`
	write_to_4bytes_binary $SIZE $OUT
	cat $OUT >> $OUT_TMP
else
	echo -en "$FILE not found.\nexit\n"
	exit -1
fi

write_to_4bytes_binary $ATAGS_ADDR $OUT
cat $OUT >> $OUT_TMP
write_to_4bytes_binary $PAD $OUT
cat $OUT >> $OUT_TMP

write_to_padding_binary $HEADER_SIZE
cat $OUT_TMP padding > $OUT


## Kernel Binary
FILE="$BOOT_DIR/zImage"
if [ -e $FILE ]; then
	echo -en " *zImage "
	cat $OUT $FILE > $OUT_TMP

	SIZE=`du -b $FILE | awk '{print $1}'`
	echo -en "$SIZE[B]\n"

	write_to_padding_binary $SIZE
	cat $OUT_TMP padding > $OUT
else
	echo -en "zImage not found.\nexit\n"
	exit -1
fi


## merged-dtb Binary
FILE="$BOOT_DIR/merged-dtb"
if [ -e $FILE ]; then
	echo -en " *merged-dtb "
	cat $OUT $FILE > $OUT_TMP

	SIZE=`du -b $FILE | awk '{print $1}'`
	echo -en "$SIZE[B]\n"

	write_to_padding_binary $SIZE
	cat $OUT_TMP padding > $OUT
else
	echo -en "merged-dtb not found.\nexit\n"
	exit -1
fi


## END
rm -f $OUT_TMP
rm -f padding
rm -f $OUT_DIR/$OUT
mv -f $OUT $OUT_DIR/

S=`du -b $OUT_DIR/$OUT | awk '{print $1}'`
S_K=$(($S/1024))
echo -en "## OUT: $OUT size: $S[B]; $S_K[K]\n"
