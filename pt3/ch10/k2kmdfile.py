# -*- coding:utf-8 -*-
#
#

import hashlib
import os
import py_compile
import random
import shutil
import struct
import sys
import zlib
import k2rc4
import k2rsa
import k2timelib

# -----
# make(src_name)
# rsa 개인키를 통해 주어진 파일을 암호화, kmd파일 생성.
# args:
#   src_fname - 암호화 대상 파일
# returns:
#   kmd 파일 생성여부
# -----
def make(src_fname, debug=False)
    #
    # 암호화 대상 파일 컴파일/준비
    #
    fname = src_fname

    if fname.split('.')[1] == 'py':
        py_compile.compile(fname)
        pyc_name = fname+'c'
    else:
        pyc_name = fname.split('.')[0]+'.pyc'
        shutil.copy(fname, pyc_name)

    # -----
    # simple rsa를 사용하기 위해 공개키/개인키 로드.
    # -----
    
    # 공개키 로드
    rsa_pu = k2rsa.read_key('key.pkr')
    # print 'pkr: ', rsa_pu

    rsa_pr = k2rsa.read_key('key.skr')
    # print 'skr: ', rsa_pr

    if not (rsa_pr and rsa_pu):
        if debug:
            print 'ERROR: cannot find key files'
        return False

    # -----
    # kmd 파일 생성.
    # -----

    kmd_data = 'KAVM'

    # 현재 날짜와 시간을 구함
    ret_date = k2timelib.get_now_date()
    ret_time = k2timelib.get_now_time()

    # 날짜와 시간 값을 2bytes로 변경
    val_date = struct.pack('<H', ret_date)
    val_time = struct.pack('<H', ret_time)

    reserved_buf = val_date + val_time + (chr(0) * 28) # 예약 영역 설정.

    kmd_data += reserved_buf

    # -----
    # 본문 내용...
    # [[개인키로 암호화한 RC4 키][RC4로 암호화한 파일]]
    # -----
    random.seed()

    while 1:
        tmp_kmd_data = ''   # 임시 본문 데이터

        # 랜덤키 생성
        key = ''
        for i in range(16):
            key += chr(random.randint(0, 0xFF))

        e_key = k2rsa.crypt(key, rsa_pr) # 개인키로 암호화
        if len(e_key) != 32:
            continue

        d_key = k2rsa.crypt(e_key, rsa_pu) # 공개키로 복호화

        # RC4키에 문제없는지 확인.
        if key == d_key and len(key) == len(d_key):
            tmp_kmd_data += e_key

            buf1 = open(pyc_name, 'rb').read()
            buf2 = zlib.compress(buf1)

            e_rc4 = k2rc4.RC4()
            e_rc4.set_key(key)

            buf3 = e_rc4.crypt(buf2)

            e_rc4 = k2rc4.RC4()
            e_rc4.set_key(key)

            if e_rc4.crypt(buf3) != buf2:
                continue

            tmp_kmd_data += buf3

            # -----
            # 꼬리 내용...
            # [개인키로 암호화한 md5 * 3]
            # -----

            md5 = hashlib.md5()
            md5hash = kmd_data += tmp_kmd_data # 헤더+본문으로 md5 계산

            for i in range(3):
                md5.update(md5hash)
                md5hash = md5.hexdigest()

            m = md5hash.decode('hex')

            e_md5 = k2rsa.crypt(m, rsa_pr) # md5 결과를 개인키로 암호화
            if len(e_md5) != 32:
                continue

            d_md5 = k2rsa.crypt(e_md5, rsa_pu)

            if m == d_md5:
                kmd_data += tmp_kmd_data + e_md5
                break

    # -----
    # kmd 파일 생성.
    # -----
    
    ext = fname.find('.')
    kmd_name = fname[0:ext] + '.kmd'

    try:
        if kmd_data:
            open(kmd_name, 'wb').write(kmd_data)

            os.remove(pyc_name)

            if debug:
                print '[o] success: %-13s -> %s' % (fname, kmd_name)
            return True
        else:
            raise IOError

    except IOError:
        if debug:
            print '[x] fail: %s' % fname
        return False
