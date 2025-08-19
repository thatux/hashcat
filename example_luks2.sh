# cracks OK
echo  | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 out/luks2-aes-argon2i-t4-m1024-p2-size20MiB_20250819135611.img.hash 2>&1


# [ test_1755628662 ] [ Type 34100, Attack 0, Mode single, Device-Type Cpu, Kernel-Type Optimized, Vector-Width 1 ] > Error : 1/8 not found, 0/8 not matched, 0/8 timeout, 0/8 skipped
# [ test_1755628662 ] [ Type 34100, Attack 0, Mode multi,  Device-Type Cpu, Kernel-Type Optimized, Vector-Width 1 ] > Error : 1/1 not found, 0/1 not matched, 0/1 timeout, 0/1 skipped

# [ test_1755628662 ] [ Type 34100, Attack 0, Mode single, Device-Type Cpu, Kernel-Type Optimized, Vector-Width 4 ] > Error : 1/8 not found, 0/8 not matched, 0/8 timeout, 0/8 skipped
# [ test_1755628662 ] [ Type 34100, Attack 0, Mode multi,  Device-Type Cpu, Kernel-Type Optimized, Vector-Width 4 ] > Error : 1/1 not found, 0/1 not matched, 0/1 timeout, 0/1 skipped

# doesn't crack (out/luks2-aes-argon2i-t5-m256-p8-size20MiB_20250819203748.img.hash)
echo 4724255513637423452254237007607598678894170349100164477426151479494198449562269262529317002664151256847798797401611271142538343046037292438332368731714424852579091014738113244327446375808473041669313710967531 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2i-t5-m256-p8-size20MiB_20250819203748.img.hash'


# however it does mount
loopdev=$(sudo losetup --show -f out/luks2-aes-argon2i-t5-m256-p8-size20MiB_20250819203748.img)
sudo cryptsetup open $loopdev notcracking <<< '4724255513637423452254237007607598678894170349100164477426151479494198449562269262529317002664151256847798797401611271142538343046037292438332368731714424852579091014738113244327446375808473041669313710967531'
sudo mount /dev/mapper/notcracking /mnt
sudo cat /mnt/info.txt
sudo umount /mnt
losetup -d notcracking

# only cracks 7/8 (hash is out/luks2-aes-argon2i-t5-m256-p8-size20MiB_20250819203748.img.hash of out/luks2-aes-argon2i-t5-m256-p8-size20MiB_20250819203748.img)
cat test_1755628662/34100_passwords.txt | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 test_1755628662/34100_hashes.txt


# not matched
cat test_1755633647/34100_passwords.txt | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 test_1755633647/34100_hashes.txt