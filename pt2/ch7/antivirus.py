# -*- coding:utf-8 -*-
import sys
import os
import hashlib
import zlib
import StringIO

import scanmod
import curemod

VirusDB = []    # virus.kmd파일에 이제 저장함.
vdb = []        # 가공된 악성코드 DB
sdb = []        # 가공된 악성코드 DB(특정 위치 검색용)
vsize = []      # 악성코드의 파일 크기만


''' KMD 파일을 복호화함
args: fname
returns: 복호화된 내용을 리턴.
    에러발생시: None 리턴
'''
def DecoderKMD(fname):
    try:
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()

        buf2 = buf[:-32]
        fmd5 = buf[-32:]

        f = buf2
        for i in range(3):
            md5 = hashlib.md5()
            md5.update(f)
            f = md5.hexdigest()

        if f != fmd5:
            raise SystemError

        buf3 = ''
        for c in buf2[4:]:  # 0xff로 xor 수행
            buf3 += chr(ord(c) ^ 0xFF)

        buf4 = zlib.decompress(buf3)
        return buf4

    except:
        pass

    return None


''' virus.kmd 파일에서 악성코드 패턴을 로드.
args: none
return: none

VirusDB 값에 저장.
'''
def LoadVirusDB():
    buf = DecodeKMD('virus.kmd')
    fp = StringIO.StringIO(buf)

    while True:
        line = fp.readline()
        if not line: break

        line = line.strip()
        VirusDB.append(line)    # 악성코드 패턴을 한줄씩 추가

    fp.close()

        
'''VirusDB를 가공하여 vdb에 저장.
args: none
returns: none
'''
def MakeVirusDB():
    for pattern in VirusDB:
        t = []
        v = pattern.split(':')
        
        scan_func = v[0]
        cure_func = v[1]
        
        if scan_func == 'ScanMD5':
            t.append(v[3])
            t.append(v[4])
            vdb.append(t)

            size = int(v[2])
            if vsize.count(size) == 0:
                vsize.append(size)

        elif scan_func == 'ScanStr':
            t.append(int(v[2]))
            t.append(v[3])
            t.append(v[4])
            sdb.append(t)


if __name__ == '__main__':
    LoadVirusDB()
    MakeVirusDB()

    if len(sys.argv) != 2:
        print 'Usage: antivirus.py [file]'
        exit(0)

    fname = sys.argv[1]

    ret, vname = scanmod.ScanVirus(fname)
    if ret == True:
        print '%s: %s' % (fname, vname)
        curemod.CureDelete(fname)    # 파일 삭제!
    else:
        print '%s: virus not found.' % (fname)
