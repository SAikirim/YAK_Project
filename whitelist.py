## YAK_Project
## https://github.com/SAikirim/YAK_Project.git

import hashlib
import ctypes
from Preprocessing_v5_0 import All_Check

##디버거용 : #ctypes.windll.user32.MessageBoxW(None, "file_name", "임포트", 0)

# md5_hash.txt 읽어오기
def loadDB():
    patterns = []
    try:
        with open('C:\\Users\\user\\Desktop\\md5_hash.txt', 'rb') as fp:
        #fp = open('md5_hash.txt', 'rb')
            while True:
                line = fp.readline()    
                if not line:
                    break
                line = line.strip()
                patterns.append(line)
    except:
        print("새 파일 생성")
        fp = open('C:\\Users\\user\\Desktop\\md5_hash.txt', 'w')
        fp.close()
    return patterns

# 검사 종료 후 md5_hash.txt 에 저장하기
def saveDB(fmd5):
##    fp = open(file_name, 'rb')
##    fbuf = fp.read()
##    fp.close()
##
##    m = hashlib.md5()
##    m.update(fbuf)
##    fmd5 = m.hexdigest()
    
    fp = open('C:\\Users\\user\\Desktop\\md5_hash.txt', 'a')
    fp.write('{0}\n'.format(fmd5))
    fp.close()

def whiteListCheck(file_name):
    # ctypes.windll.user32.MessageBoxW(None, file_name, "PATH", 0) # 디버그용
    try:
        fp = open(file_name, 'rb')
        fbuf = fp.read()
        fp.close()

        m = hashlib.md5()
        m.update(fbuf)
        fmd5 = m.hexdigest()
    
        db = loadDB()
            
        for i in db:
            i = i.decode('utf-8')
        # 화이트리스트에 저장되어있으면 바이러스 아님, 딥러닝 검사 안함
            if fmd5 == i:
                print('no virus')
                return 0
            else:
                continue
        # 화이트 리스트에 없으므로 딥러닝으로 검사
        result = All_Check(file_name)
    except Exception as e:
            excep = str(e)
            ctypes.windll.user32.MessageBoxW(None, excep, "Exception", 0)
            return 4
        
    if 0 == result:
        saveDB(fmd5)
        add_whitelist = "Whitelist를 추가하였습니다."
        ctypes.windll.user32.MessageBoxW(None, add_whitelist, "Whitelist", 0)
        return result
    else:
        return result
        

if __name__ == "__main__":
    #path = r"C:\Users\user\source\repos\Yak_project\nomal1.vir"
    #path = r"C:\Users\user\source\repos\Yak_project\nomal2.vir"
    #path = r"C:\Users\user\source\repos\Yak_project\nomal3.vir"
    path = r"C:\Program Files\Internet Explorer\iexplore.exe"
    #path = r"C:\Windows\System32\calc.exe"
    #path = 'C:/Users/user/source/repos/Yak_project/infected.vir'
    #path = 'C:/Users/user/source/repos/Yak_project/infected2.vir'
    #path = 'C:/Users/user/source/repos/Yak_project/infected3.vir'
    print(whiteListCheck(path))
