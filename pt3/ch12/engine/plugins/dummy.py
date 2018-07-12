# -*- coding:utf-8 -*-
#
#
# dummy파일에 대한 플러그인 엔진.

class KavMain:


    def init(self, plugins_path):
        self.virus_name = 'l4in test file(not a virus)'
        self.dummy_pattern = 'serial experiments l4in rules!'

        return 0


    def uninit(self):
        del self.virus_name
        del self.dummy_pattern

        return 0

    
    def scan(self, filehandle, filename):
        try:
            fp = open(filename)
            buf = fp.read(len(self.dummy_pattern))
            fp.close()

            if buf == self.dummy_pattern:
                return True, self.virus_name, 0

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
        vlist = list()

        vlist.append(self.virus_name)

        return vlist


    def getinfo(self):
        info = dict()

        info['author'] = 'l4in'
        info['version'] = '0.01'
        info['title'] = 'l4in file scan engine'
        info['kmd_name'] = 'dummy'

        return info

