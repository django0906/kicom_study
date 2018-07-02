# -*- coding:utf-8 -*-

import k2rsa
import k2kmdfile

pu = k2rsa.read_key('key.pkr')
k = k2kmdfile.KMD('dummy.kmd', pu)

module = k2kmdfile.load('dummy', k.body)
print dir(module)

'''
case 1. kmdfile.load의 리턴값을 이용해 모듈 사용.
'''


kav = module.KavMain()
kav.init('.')
print kav.getinfo()
kav.uninit()

'''
case 2. 모듈 동적로딩을 하면 import를 한 후의 사용도 가능하다.
'''
import dummy

kav2 = dummy.KavMain()
kav2.init('.')
print kav2.listvirus()
kav2.uninit()
