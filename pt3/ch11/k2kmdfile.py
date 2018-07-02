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

import marshal
import imp

import k2rc4
import k2rsa
import k2timelib


# -----
# load(mod_name, buf)
# 주어진 모듈 이름으로 파이썬 코드를 메모리에 로딩한다.
# args:
#   mod_name - 모듈 이름
#   buf - 파이썬 코드(pyc 시그니처 포함)
# returns:
#   로딩된 모듈 Object
# -----
def load(mod_name, buf):
    # pyc 시그니처를 포함하는가 확인.
    if buf[:4] == '03F30D0A'.decode('hex'):
        code = marshal.loads(buf[8:])
        module = imp.new_module(mod_name) # 새로운 모듈을 생성.
        exec (code, module.__dict__)    # pyc와 모듈을 연결.
        sys.modules[mod_name] = module  # 전역에서 사용 가능하도록 등록.

        return module
    else:
        return None


# -----
# make(src_name)
# rsa 개인키를 통해 주어진 파일을 암호화, kmd파일 생성.
# args:
#   src_fname - 암호화 대상 파일
# returns:
#   kmd 파일 생성여부
# -----
def make(src_fname, debug=False):
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
            md5hash = kmd_data + tmp_kmd_data # 헤더+본문으로 md5 계산

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


# -----
# ntimes_md5(buf, ntimes)
# 주어진 버퍼에 대해 n회 반복한 후 md5 해쉬 결과를 리턴.
# args:
#   buf - 버퍼
#   ntimes - 반복횟수
# returns:
#   md5 해쉬값
# -----
def ntimes_md5(buf, ntimes):
    md5 = hashlib.md5()
    md5hash = buf
    for i in range(ntimes):
        md5.update(md5hash)
        md5hash = md5.hexdigest()

    return md5hash


# -----
# KMD 오류 메시지 정의
# -----
class KMDFormatError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# -----
# KMD 관련 상수
# -----
class KMDConstants:
    KMD_SIGNATURE = 'KAVM'

    KMD_DATE_OFFSET = 4
    KMD_DATE_LENGTH = 2
    KMD_TIME_OFFSET = 6
    KMD_TIME_LENGTH = 2

    KMD_RESERVED_OFFSET = 8
    KMD_RESERVED_LENGTH = 28

    KMD_RC4_KEY_OFFSET = 36
    KMD_RC4_KEY_LENGTH = 32

    KMD_MD5_OFFSET = -32


# -----
# KMD 클래스
# -----
class KMD(KMDConstants):
    # -----
    # __init__(self, fname, pu)
    # 클래스 초기화.
    # args:
    #   fname - KMD파일 이름
    #   pu  - 복호화를 위한 공개키
    # -----
    def __init__(self, fname, pu):
        self.filename = fname
        self.date = None
        self.time = None
        self.body = None

        self.__kmd_data = None
        self.__rsa_pu = pu
        self.__rc4_key = None

        if self.filename:
            self.__decrypt(self.filename)


    # -----
    # __decrypt(self, fname)
    # kmd 파일 복호화.
    # args:
    #   fname - KMD 파일 이름
    # -----
    def __decrypt(self, fname, debug=False):

        with open(fname, 'rb') as fp:
            # 시그니처가 맞다면 파일을 로드.
            if fp.read(4) == self.KMD_SIGNATURE:
                self.__kmd_data = self.KMD_SIGNATURE + fp.read()

            else:
                raise KMDFormatError('KMD Header magic not found.')

        #kmd 파일 날짜 로드.
        tmp = self.__kmd_data[self.KMD_DATE_OFFSET:
                            self.KMD_DATE_OFFSET + self.KMD_DATE_LENGTH]
        self.date = k2timelib.convert_date(struct.unpack('<H', tmp)[0])
        #print self.date

        #kmd 파일 시간 로드.
        tmp = self.__kmd_data[self.KMD_TIME_OFFSET:
                            self.KMD_TIME_OFFSET + self.KMD_TIME_LENGTH]
        self.time = k2timelib.convert_date(struct.unpack('<H', tmp)[0])
        #print self.time

        e_md5hash = self.__get_md5()

        # 무결성 체크
        md5hash = ntimes_md5(self.__kmd_data[:self.KMD_MD5_OFFSET], 3)
        if e_md5hash != md5hash.decode('hex'):
            raise KMDFormatError('Invalid KMD MD5 hash.')

        # RC4 키 읽기
        self.__rc4_key = self.__get_rc4_key()

        e_kmd_data = self.__get_body()
        if debug:
            print len(e_kmd_data)

        self.body = zlib.decompress(e_kmd_data)
        if debug:
            print len(self.body)


    # -----
    # __get_rs4_key(self)
    # kmd 파일의 rc4 값을 로드.
    # args: none
    # returns: rc4 키값
    # -----
    def __get_rc4_key(self):
        e_key = self.__kmd_data[self.KMD_RC4_KEY_OFFSET:
                    self.KMD_RC4_KEY_OFFSET + self.KMD_RC4_KEY_LENGTH]
        return k2rsa.crypt(e_key, self.__rsa_pu)


    # -----
    # __get_body(self)
    # kmd 파일의 body를 얻는다.
    # args: none
    # returns: kmd body
    # -----
    def __get_body(self):
        e_kmd_data = self.__kmd_data[self.KMD_RC4_KEY_OFFSET + self.KMD_RC4_KEY_LENGTH
                                :self.KMD_MD5_OFFSET]
        r = k2rc4.RC4()
        r.set_key(self.__rc4_key)
        return r.crypt(e_kmd_data)


    # -----
    # __get_md5(self)
    # kmd 파일의 md5를 얻는다.
    # args: none
    # returns: kmd 파일의 md5 값
    # -----
    def __get_md5(self):
        e_md5 = self.__kmd_data[self.KMD_MD5_OFFSET:]
        return k2rsa.crypt(e_md5, self.__rsa_pu)
