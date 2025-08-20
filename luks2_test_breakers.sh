# cracks OK
echo  | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 out/luks2-aes-argon2i-t4-m1024-p2-size20MiB_20250819135611.img.hash 2>&1
# echo  | ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:halt_on_error=1,fast_unwind_on_malloc=1:strict_string_checks=0:alloc_dealloc_mismatch=1:detect_stack_use_after_return=1 ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 out/luks2-aes-argon2i-t4-m1024-p2-size20MiB_20250819135611.img.hash 2>&1

pw="4724255513637423452254237007607598678894170349100164477426151479494198449562269262529317002664151256847798797401611271142538343046037292438332368731714424852579091014738113244327446375808473041669313710967531"
img="out/luks2-aes-argon2i-t5-m256-p8-size20MiB_20250819203748.img"
hash=$img.hash
#mounting works
loopdev=$(sudo losetup --show -f $img)
sudo cryptsetup open "$loopdev" "notcracking" <<< "$pw"
sudo mount /dev/mapper/notcracking /mnt
sudo cat /mnt/info.txt
sudo umount /mnt
sudo cryptsetup close "notcracking"
sudo losetup -d $loopdev
#cracking does not work
echo $pw | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 "$hash"

# smaller password that doesn't crack
pw="0345679006880395984065151993862430373984899197156293374473453587"
img="out/luks2-aes-argon2id-t5-m128-p1-size20MiB_20250820011624.img"
hash=$img.hash
#mounting works
loopdev=$(sudo losetup --show -f $img)
sudo cryptsetup open "$loopdev" "notcracking" <<< "$pw"
sudo mount /dev/mapper/notcracking /mnt
sudo cat /mnt/info.txt
sudo umount /mnt
sudo cryptsetup close "notcracking"
sudo losetup -d $loopdev
#cracking does not work
echo $pw | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 "$hash"
# ASAN doesn't detect any errors
# echo 0345679006880395984065151993862430373984899197156293374473453587 | ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:halt_on_error=1,fast_unwind_on_malloc=1:strict_string_checks=0:alloc_dealloc_mismatch=1:detect_stack_use_after_return=1 ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 "out/luks2-aes-argon2id-t5-m128-p1-size20MiB_20250820011624.img.hash"

#list of hashes that don't crack
# $ grep -ri 'password not found' test_17556* | rev | cut -d' ' -f1 | rev | grep -F '.hash'
# '/tmp/out/luks2-aes-argon2i-t5-m256-p8-size20MiB_20250819203748.img.hash'
# '/tmp/out/luks2-aes-argon2i-t5-m256-p8-size20MiB_20250819203748.img.hash'
# '/tmp/out/luks2-aes-argon2id-t5-m128-p1-size20MiB_20250820011624.img.hash'
# '/tmp/out/luks2-aes-argon2id-t5-m128-p1-size20MiB_20250820011624.img.hash'
# '/tmp/out/luks2-aes-argon2i-t6-m64-p2-size20MiB_20250820012705.img.hash'
# '/tmp/out/luks2-aes-argon2i-t6-m64-p2-size20MiB_20250820012705.img.hash'
# '/tmp/out/luks2-aes-argon2id-t5-m16-p1-size20MiB_20250820013520.img.hash'
# '/tmp/out/luks2-aes-argon2i-t6-m1024-p4-size20MiB_20250820013521.img.hash'
# '/tmp/out/luks2-aes-argon2id-t5-m16-p1-size20MiB_20250820013520.img.hash'
# '/tmp/out/luks2-aes-argon2i-t6-m1024-p4-size20MiB_20250820013521.img.hash'
# '/tmp/out/luks2-aes-argon2id-t4-m32-p8-size20MiB_20250820014704.img.hash'
# '/tmp/out/luks2-aes-argon2id-t4-m32-p8-size20MiB_20250820014704.img.hash'
# '/tmp/out/luks2-aes-argon2id-t6-m32-p2-size20MiB_20250820044335.img.hash'
# '/tmp/out/luks2-aes-argon2id-t6-m32-p2-size20MiB_20250820044335.img.hash'
# '/tmp/out/luks2-aes-argon2i-t5-m64-p2-size20MiB_20250820045152.img.hash'
# '/tmp/out/luks2-aes-argon2i-t5-m64-p2-size20MiB_20250820045152.img.hash'
# '/tmp/out/luks2-aes-argon2id-t6-m128-p4-size20MiB_20250820053930.img.hash'
# '/tmp/out/luks2-aes-argon2id-t6-m128-p4-size20MiB_20250820053930.img.hash'
# '/tmp/out/luks2-aes-argon2id-t4-m128-p2-size20MiB_20250820062428.img.hash'
# '/tmp/out/luks2-aes-argon2id-t5-m128-p4-size20MiB_20250820062430.img.hash'
# '/tmp/out/luks2-aes-argon2id-t4-m128-p2-size20MiB_20250820062428.img.hash'
# '/tmp/out/luks2-aes-argon2id-t5-m128-p4-size20MiB_20250820062430.img.hash'
# '/tmp/out/luks2-aes-argon2i-t6-m16-p1-size20MiB_20250820070332.img.hash'
# '/tmp/out/luks2-aes-argon2i-t6-m16-p1-size20MiB_20250820070332.img.hash'
# '/tmp/out/luks2-aes-argon2i-t6-m128-p2-size20MiB_20250820071602.img.hash'
# '/tmp/out/luks2-aes-argon2i-t6-m128-p2-size20MiB_20250820071602.img.hash'
# '/tmp/out/luks2-aes-argon2id-t5-m128-p8-size20MiB_20250820082710.img.hash'
# '/tmp/out/luks2-aes-argon2id-t5-m128-p8-size20MiB_20250820082710.img.hash'
# not really a clue on what's wrong; all options are in there: argon2 and argon2id, t4,t5,t6, m16-1024, p2-8
