# -*- coding:utf-8 -*-
#
#
# eicar파일에 대한 플러그인 엔진.

class KavMain:


    def init(self, plugins_path):
        self.virus_name = 'EICAR test file(not a virus)'
        self.dummy_pattern = 'EICAR-TEST-FILE'

        return 0


    def uninit(self):
        del self.virus_name
        del self.dummy_pattern

        return 0

    
    def scan(self, filehandle, filename):
        try:
            # memory-mapped file을 이용한 파일 입출력 속도 향상.
            mm = filehandle

            size = os.path.getsize(filename)
            if size == 68:
                m = hashlib.md5()
                m.update(mm[:68])
                fmd5 = m.hexdigest()

                if fmd5 == '':
                    return True, 'EICAR test file(not a virus)'

        except IOError:
            pass

        # 악성코드 미탐지시 리턴
        return False, '', -1


    def disinfect(self, filename, malware_id):
        try:
            if malware_id == 0:
                os.remove(filename)
                return True

        except IOError:
            pass

        # 악성코드 치료 실패
        return False


    def listvirus(self):
        vlust = list()

        vlist.append(self.virus_name)

        return vlist


    def getinfo(self):
        info = dict()

        info['author'] = 'l4in'
        info['version'] = '0.01'
        info['title'] = 'EICAR scan engine'
        info['kmd_name'] = 'eicar'

        return info

