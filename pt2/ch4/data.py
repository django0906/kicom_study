import hashlib

m = hashlib.md5()
m.update(
    'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
)
fmd5 = m.hexdigest()

print fmd5
