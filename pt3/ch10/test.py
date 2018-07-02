import k2rsa
import k2kmdfile

k2rsa.create_key('key.pkr', 'key.skr')

ret = k2kmdfile.make('textfile.txt')

if ret:
    pu = k2rsa.read_key('key.pkr')
    k = k2kmdfile.KMD('textfile.kmd', pu)
    print k.body
