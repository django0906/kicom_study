# -*- coding:utf-8 -*-
import sys
import zlib
import hashlib
import os


def main():
    if len(sys.argv) != 2:
        print 'Usage: kmake.py [file]'
        return

    fname = sys.argv[1]
    tname = fname

    fp = open(tname, 'rb')
    buf = fp.read()
    fp.close()

    buf2 = zlib.compress(buf)

    buf3 = ''
    for c in buf2:
        buf3 += chr(ord(c) ^ 0xFF)  # 압축한 내용을 XOR함.

    buf4 = 'KAVM' + buf3

    f = buf4
    for i in range(3):
        md5 = hashlib.md5()
        md5.update(f)
        f = md5.hexdigest()

    buf4 += f

    kmd_name = fname.split('.')[0] + '.kmd'
    fp = open(kmd_name, 'wb')
    fp.write(buf4)
    fp.close()

    print '%s -> %s' % (fname, kmd_name)


if __name__ == '__main__':
    main()
