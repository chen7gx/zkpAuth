#!/usr/bin/bash
#删除原文件
rm id.zok
#重新生成.zok文件
cat>id.zok<<EOF
//请勿修改此文件
import "hashes/sha256/256bitPadded.zok" as sha256
import "utils/pack/u32/nonStrictUnpack256.zok" as unpack256
import "utils/pack/u32/pack256.zok" as pack256

def main(private field identity,field rnd)->bool:
u32[8] id= unpack256(identity)
u32[8] idhash=sha256(id)
field identityHash=pack256(idhash)
field Rnd= 10
bool allow=false
field [1] permission =[
0]
for u32 i in 0..1 do
        allow=allow || (if identityHash==permission[i] then true else false fi)
endfor
	allow=allow &&(if rnd ==Rnd then true else false fi)
return allow
EOF



number=1   #记录拥有权限的用户的数量number-1
#生成md5,并写入文件赋予访问权限
while read identityID
do
        cd hash
        zokrates compute-witness -a $identityID
        string=`head -1 witness`
        A=${string:6}
        cd ..
        sed -i "12a $A," id.zok  #写入文件
        #更改数组及大小
        Number=`expr $number + 1`
        sed -i "12s/$number/$Number/" id.zok
        clo=`expr $number + 14`
        #更改循环大小
        sed -i "$clo s/0.."$number"/0.."$Number"/" id.zok
        number=$Number
done < IDfile
echo "id.zok:"
cat id.zok
