# -*- coding:utf-8 -*-
import sys
import os
import hashlib

VirusDB = [
        '68:abcd:EICAR test',
        '65:asdb:Dummy test'
]

vdb = []    # 가공된 악성코드 DB
vsize = []  # 악성코드의 파일 크기만


'''VirusDB를 가공하여 vdb에 저장.
args: none
returns: none
'''
def MakeVirusDB():
    for pattern in VirusDB:
        t = []
        v = pattern.split(':')
        t.append(v[1])
        t.append(v[2])
        vdb.append(t)   # 최종 vdb완성


'''악성코드 검사.
args: fmd5
returns: none
'''
def SearchVDB(fmd5):
    for t in vdb:
        if t[0] == fmd5:
            return True, t[1]

    return False, ''    # 악성코드 탐지되지 않음


if __name__ == '__main__':
    MakeVirusDB()

    if len(sys.argv) != 2:
        print 'Usage: antivirus.py [file]'
        exit(0)

    fname = sys.argv[1]

    size = os.path.getsize(fname)
    if vsize.count(size):
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()

        m = hashlib.md5()
        m.update(buf)
        fmd5 = m.hexdigest()

        ret, vname = SearchVDB(fmd5)
        if ret == True:
            print '%s: %s' % (fname, vname)
            os.remove(fname)    # 파일 삭제!
        else:
            print '%s: virus not found.' % (fname)
    else:
        print '%s: virus not found.' % (fname)
