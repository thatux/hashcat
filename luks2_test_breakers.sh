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
# echo "0345679006880395984065151993862430373984899197156293374473453587" | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 "out/luks2-aes-argon2id-t5-m128-p1-size20MiB_20250820011624.img.hash"
# ASAN doesn't detect any errors
# echo 0345679006880395984065151993862430373984899197156293374473453587 | ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:halt_on_error=1,fast_unwind_on_malloc=1:strict_string_checks=0:alloc_dealloc_mismatch=1:detect_stack_use_after_return=1 ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 "out/luks2-aes-argon2id-t5-m128-p1-size20MiB_20250820011624.img.hash"

#list of hashes that don't crack
# $ grep -ri 'password not found' test_17556* | rev | cut -d' ' -f1 | rev | grep -F '.hash'
# 'out/luks2-aes-argon2i-t5-m256-p8-size20MiB_20250819203748.img.hash'
# 'out/luks2-aes-argon2i-t5-m256-p8-size20MiB_20250819203748.img.hash'
# 'out/luks2-aes-argon2id-t5-m128-p1-size20MiB_20250820011624.img.hash'
# 'out/luks2-aes-argon2id-t5-m128-p1-size20MiB_20250820011624.img.hash'
# 'out/luks2-aes-argon2i-t6-m64-p2-size20MiB_20250820012705.img.hash'
# 'out/luks2-aes-argon2i-t6-m64-p2-size20MiB_20250820012705.img.hash'
# 'out/luks2-aes-argon2id-t5-m16-p1-size20MiB_20250820013520.img.hash'
# 'out/luks2-aes-argon2i-t6-m1024-p4-size20MiB_20250820013521.img.hash'
# 'out/luks2-aes-argon2id-t5-m16-p1-size20MiB_20250820013520.img.hash'
# 'out/luks2-aes-argon2i-t6-m1024-p4-size20MiB_20250820013521.img.hash'
# 'out/luks2-aes-argon2id-t4-m32-p8-size20MiB_20250820014704.img.hash'
# 'out/luks2-aes-argon2id-t4-m32-p8-size20MiB_20250820014704.img.hash'
# 'out/luks2-aes-argon2id-t6-m32-p2-size20MiB_20250820044335.img.hash'
# 'out/luks2-aes-argon2id-t6-m32-p2-size20MiB_20250820044335.img.hash'
# 'out/luks2-aes-argon2i-t5-m64-p2-size20MiB_20250820045152.img.hash'
# 'out/luks2-aes-argon2i-t5-m64-p2-size20MiB_20250820045152.img.hash'
# 'out/luks2-aes-argon2id-t6-m128-p4-size20MiB_20250820053930.img.hash'
# 'out/luks2-aes-argon2id-t6-m128-p4-size20MiB_20250820053930.img.hash'
# 'out/luks2-aes-argon2id-t4-m128-p2-size20MiB_20250820062428.img.hash'
# 'out/luks2-aes-argon2id-t5-m128-p4-size20MiB_20250820062430.img.hash'
# 'out/luks2-aes-argon2id-t4-m128-p2-size20MiB_20250820062428.img.hash'
# 'out/luks2-aes-argon2id-t5-m128-p4-size20MiB_20250820062430.img.hash'
# 'out/luks2-aes-argon2i-t6-m16-p1-size20MiB_20250820070332.img.hash'
# 'out/luks2-aes-argon2i-t6-m16-p1-size20MiB_20250820070332.img.hash'
# 'out/luks2-aes-argon2i-t6-m128-p2-size20MiB_20250820071602.img.hash'
# 'out/luks2-aes-argon2i-t6-m128-p2-size20MiB_20250820071602.img.hash'
# 'out/luks2-aes-argon2id-t5-m128-p8-size20MiB_20250820082710.img.hash'
# 'out/luks2-aes-argon2id-t5-m128-p8-size20MiB_20250820082710.img.hash'
# not really a clue on what's wrong; all options are in there: argon2 and argon2id, t4,t5,t6, m16-1024, p2-8

# save all files
# grep -ri 'password not found' test_17556* | rev | cut -d' ' -f1 | rev | grep -F '.hash' | sed "s/[\"']//g" | sed "s/\.hash//g" | while read f; do echo $f; cp $f* out/; done
# save all attacks
# grep -ri 'password not found' test_17556* | cut -d':' -f3 |  grep -F '.hash' | grep -F 'backend-vector-width 1' | cut -c2- | sort -u
echo 02287730953744628870985593362198435375620503348007868720988912710184832550872076801290310768814053635053860521386482916393577168804444037087874356401700298709138519444703625433600472131279821488077969 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2i-t6-m1024-p4-size20MiB_20250820013521.img.hash'
echo 0345679006880395984065151993862430373984899197156293374473453587 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2id-t5-m128-p1-size20MiB_20250820011624.img.hash'
echo 092716992067403233252313393903721300734140880391054076903189463965468444734759793085092208358915927608346472113431131955747291957347211075230084374387836493635520801029311920288416279313090562580508654717694099523011 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2id-t6-m32-p2-size20MiB_20250820044335.img.hash'
echo 105652937830011868886357957934121934750125952320205996690359342275819776846914900624783331411193827179567405757137725746172134016733139181432258641938334127586141841969618481047152107241287546833129124229920845082589705130674515 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2i-t5-m64-p2-size20MiB_20250820045152.img.hash'
echo 1922469771464508431870616480582073688372297197898457493620148193 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2i-t6-m64-p2-size20MiB_20250820012705.img.hash'
echo 20715796298165638929199608987398858551118249353852386788523592992442437727432073 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2id-t5-m16-p1-size20MiB_20250820013520.img.hash'
echo 217477661849793305564605636484552327148417108403102506985107718467839335621974361380819535702532 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2i-t6-m128-p2-size20MiB_20250820071602.img.hash'
echo 374775505382147353565438052154677880530475349648612138532046562862377075782364584606063347688030 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2id-t4-m128-p2-size20MiB_20250820062428.img.hash'
echo 393259545233806581366990442679198036189958060530126397968494922365670673400572447994882593037799768089420326711745136239783396890673116008622472378826175487062391712339079281184227090071460936607466927483514620523881074659331529 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2id-t5-m128-p4-size20MiB_20250820062430.img.hash'
echo 46077772389265887919949570209384719734401656195311380803350406753901240629193125 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2i-t6-m16-p1-size20MiB_20250820070332.img.hash'
echo 4724255513637423452254237007607598678894170349100164477426151479494198449562269262529317002664151256847798797401611271142538343046037292438332368731714424852579091014738113244327446375808473041669313710967531 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2i-t5-m256-p8-size20MiB_20250819203748.img.hash'
echo 6099764068910182982816969215608518920569179782649857896975804220 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2id-t5-m128-p8-size20MiB_20250820082710.img.hash'
echo 6628256105782870142991529512339996019300535171995446617664454830176772268326017249979236 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2id-t6-m128-p4-size20MiB_20250820053930.img.hash'
echo 78561619564772367582757348828498697051534478779324101746263617520087966732714864 | ./hashcat --quiet --potfile-disable --logfile-disable -D 1 -O --runtime 400 --backend-vector-width 1 -a 0 -m 34100 'out/luks2-aes-argon2id-t4-m32-p8-size20MiB_20250820014704.img.hash'
# all the above don't crack

pw="78561619564772367582757348828498697051534478779324101746263617520087966732714864"
img="out/luks2-aes-argon2id-t4-m32-p8-size20MiB_20250820014704.img"
hash=$img.hash
#but they all mount just fine
loopdev=$(sudo losetup --show -f $img)
sudo cryptsetup open "$loopdev" "notcracking" <<< "$pw"
sudo mount /dev/mapper/notcracking /mnt
sudo cat /mnt/info.txt
sudo umount /mnt
sudo cryptsetup close "notcracking"
sudo losetup -d $loopdev