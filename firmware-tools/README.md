# Extract device key

## Obtain original firmware

Read the SPI Flash from Pokemon GO Plus, name it ``pogoplus.bin``

If you are using Raspberry Pi:
```
flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=1000 -r pogoplus.bin
```

## decrypt original firmware

run decrypt.py, it will generate dec.bin which is the decrypted firmware file. The md5sum of ```dec.bin``` should be ```07604430d3032bb14f84e8c8daff9d6e```

Patch the firmware at location 25637 (decimal). We can do this using standard command line tools:

## Patch original firmware
```
#create a copy of the file
cp dec.bin patched.bin
#patch the copy
printf '\x7c' | dd  bs=1 seek=25636 count=1 conv=notrunc of=patched.bin
cmp -l dec.bin patched.bin
#it should show: 25637 114 174
#the offset of cmp starts at 1 and shows octal difference
```
MD5 sum of patched file should be ```51619c86b15d3ae19adaf2bf6e896749```

## Reencrypt patched firmware

Make sure ```pogoplus.bin``` (the original firmware) is in the same directory as ```patched.bin```, then run
```
python patch.py patched.bin
```
Result will be ```result.bin```

## Flash patched firmware

```
 flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=1000 -w result.bin 
```

## Read the key
Read the challenge using any BLE debugging app. Last 16 bytes is the device key.

## Restore the old firmware

```
 flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=1000 -w pogoplus.bin 
```


