# -*- coding:utf-8 -*-
#
#

import os
import StringIO
import datetime

import k2kmdfile
import k2rsa

# -----
# Engine 저장소
# -----
class Engine:
    # -----
    # __init__(self, debug=False)
    # 클래스 초기화.
    # args:
    #   debug - 디버그 여부
    # -----
    def __init__(self, debug=False):
        self.debug = debug

        self.plugins_path = None
        self.kmdfiles = []
        self.kmd_modules = []

        self.max_datetime = datetime.datetime(1980, 1, 1, 0, 0, 0, 0)

    # -----
    # set_plugins(self, plugins_path)
    # 주어진 경로에서 플러그인 엔진을 로딩 준비한다.
    # args:
    #   plugins_path - 플러그인 엔진 경로
    # returns:
    #   성공여부
    # -----
    def set_plugins(self, plugins_path):
        self.plugins_path = plugins_path

        pu = k2rsa.read_key(plugins_path + os.sep + 'key.pkr')
        if not pu:
            return False

        ret = self.__get_kmd_list(plugins_path + os.sep + 'kicom.kmd', pu)

        if not ret:
            return False

        if self.debug:
            print '[*] kicom.kmd :'
            print ' ', self.kmdfiles

        for kmd_name in self.kmdfiles:
            kmd_path = plugins_path + os.sep + kmd_name
            k = k2kmdfile.KMD(kmd_path, pu)
            module = k2kmdfile.load(kmd_name.split('.')[0], k.body)
            if module:
                self.kmd_modules.append(module)
                self.__get_last_kmd_build_time(k)

        if self.debug:
            print '[*] kmd_modules :'
            print ' ', self.kmd_modules
            print '[*] Last updated %s UTC' % self.max_datetime.ctime()
        
        return True


    # -----
    # __get_kmd_list(self, kicom_kmd_file, pu)
    # 플러그인 엔진의 로딩 우선순위를 알아낸다.
    # args:
    #   kicom_kmd_file - kicom.kmd 파일의 전체 경로
    #   pu - 공개키
    # returns:
    #   성공여부
    # -----
    def __get_kmd_list(self, kicom_kmd_file, pu):
        kmdfiles = []

        k = k2kmdfile.KMD(kicom_kmd_file, pu)

        if k.body:
            msg = StringIO.StringIO(k.body)

            while True:
                line = msg.readline().strip()

                if not line:
                    break
                elif line.find('.kmd') != -1:
                    kmdfiles.append(line)
                else:
                    continue

        if len(kmdfiles):
            self.kmdfiles = kmdfiles
            return True
        else:
            return False


    # -----
    # __get_last_kmd_build_time(self, kmd_info)
    # 복호화된 플러그인 엔진의 빌드시간 값 중 가장 최신 값을 보관한다.
    # args:
    #   kmd_info - 복호화된 플러그인 엔진 정보
    # -----
    def __get_last_kmd_build_time(self, kmd_info):
        d_y, d_m, d_d = kmd_info.date
        t_h, t_m, t_s = kmd_info.time
        t_datetime = datetime.datetime(d_y, d_m, d_d, t_h, t_m, t_s)

        if self.max_datetime < t_datetime:
            self.max_datetime = t_datetime


    # -----
    # create_instance(self)
    # 백신 엔진의 인스턴스를 생성한다.
    # -----
    def create_instance(self):
        ei = EngineInstance(self.plugins_path, self.max_datetime, self.debug)
        if ei.create(self.kmd_modules):
            return ei
        else:
            return None


# -----
# EngineInstance 클래스
# -----
class EngineInstance:
    # -----
    # __init__(self, plugins_path, max_datetime, debug=False)
    # 클래스 초기화.
    # args:
    #   plugins_path - 플러그인 엔진 경로
    #   max_datetime - 플러그인 엔진의 최신 시간 값
    #   debug - 디버그 여부
    # -----
    def __init__(self, plugins_path, max_datetime, debug=False):
        self.debug = debug
        self.plugins_path = plugins_path
        self.max_datetime = max_datetime

        self.kavmain_inst = []


    # -----
    # create(self, kmd_modules)
    # 백신 엔진의 인스턴스 생성.
    # args:
    #   kmd_modules - 메모리에 로딩된 kmd 모듈 리스트
    # returns:
    #   성공여부
    # -----
    def create(self, kmd_modules):
        for mod in kmd_modules:
            try:
                t = mod.KavMain()
                self.kavmain_inst.append(t)
            except AttributeError:
                continue

        if len(self.kavmain_inst):
            if self.debug:
                print '[*] count of KavMain: %d' % (len(self.kavmain_inst))
                return True
            else:
                return False
