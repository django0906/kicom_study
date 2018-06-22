import hashlib
import os

fp = open('eicar.txt', 'rb')
fbuf = fp.read()
fp.close()

m = hashlib.md5()
m.update(fbuf)
fmd5 = m.hexdigest()

print fmd5

if fmd5 == '44d88612fea8a8f36de82e1278abb02f':
    print '[!] Virus detected'
    os.remove('eicar.txt')
else:
    print '[o] There\'s no virus'
