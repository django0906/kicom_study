# -*- coding:utf-8 -*-
import os
import hashlib


'''악성코드 검사.
args: fmd5
returns: none
'''
def SearchVDB(fmd5):
    for t in vdb:
        if t[0] == fmd5:
            return True, t[1]

    return False, ''    # 악성코드 탐지되지 않음


'''
MD5를 이용하여 악성코드를 검사한다.
args: fname
returns: 악성코드의 이름, 혹은 None
'''
def ScanMD5(fname):
    ret = False
    vname = ''

    size = os.path.getsize(fname)
    if vsize.count(size):
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()

        m = hashlib.md5()
        m.update(buf)
        fmd5 = m.hexdigest()

        ret, vname = SearchVDB(fmd5)
    
    return ret, vname


''' 악성코드 검색을 수행.
args: vdb, vsize, sdb, fname
returns: 악성코드가 있다면 리턴
아니면 다른 함수의 결과대로.
'''
def ScanVirus(vdb, vsize, sdb, fname):
    ret, vname = ScanMD5(vdb, vsize, fname)
    if ret == True:
        return ret, vname

    fp = open(fname, 'rb')
    for t in sdb:
        if ScanStr(fp, t[0], t[1]) == True:
            ret = True
            vname = t[2]
            break
    fp.close()

    return ret, vname
