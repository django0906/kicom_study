# -*- coding:utf-8 -*-

def ScanStr(fp, offset, mal_str):
    size = len(mal_str)

    fp.seek(offset)
    buf = fp.read(size)

    if buf == mal_str:
        return True
    else:
        return False
