# YAK_Project

- OT에서 딥러닝을 활용한 악성코드 탐지

## 기능

- **yak.exe(32bit)**
    - 전체 또는 특정 프로세스에 대해 후킹하여 DLL 인젝션 가능
        - 'explorer.exe'에만 인젝션하도록 변경
    - 인젝션, 이젝션 가능

- **MalDetecter.dll(32bit)**
    - 글로벌 후킹 기능
    - whitelist 확인 가능
    - server와 통신
    - 새로 만들어지는 자식 프로세스를 확인후
        - True : 프로세스 종료
        - False : 프로세스 통과
    - 프로세스를 종료하기 전에 메시지박스를 출력해 '종료 여부' 확인 가능


- **preprocessing.py(32bit)**
    - 파일 정보를 전달 받은 후 배열로 값 전처리
    - 전처리 후 server로 데이터 전달

- **whitelist.py(32bit)**
    - whitelist와 파일의 해쉬값 비교,  리스트에 존재하면 검사 단계 PASS
    - 검사 후, 악성코드로 판별되면 whitelist에 해쉬값 자동 저장

- **server.py(64bit)**
    - preprocessing.py로부터 받은 데이터로 모델 예측함
    - 0과 1로 예측값을 리턴함

- **strings.exe**
	- IP와 URL의 string을 추출하기위한 외부 프로그램
	
- **model_v7_6_940533.h5**
	- v7.6 버전의 에이전트에 쓰는 딥러닝 모델

### 에이전트 파일 공유

[https://github.com/SAikirim/YAK_Project.git](https://github.com/SAikirim/YAK_Project.git)

---

## 사전 환경

- win_xp / win_7(32bit)
    - Python(v3.7.2)
        - pip로 설치한 패키지 : lief(0.10.1), requests(2.25.0)
- wint_7(64bit)
    - Python(v3.8.6)
        - pip로 설치한 패키지 :  Flask(1.1.2), tesnsorflow(2.3.1), Keras(2.4.3), 기타 선행 패키지

## 사용법

1. 서버로 사용될 win_7(64bit)에 server.py와 moel.h5를 같은 폴더에 둔다
2. 콘솔 명령창에서 server.py를 실행시킨다.
    - Ex) `python server.py`

---

1. whitelist.py, preprocessing.py, strings.exe를 파이썬 라이브러리에 복사한다.
    - Ex) 'C:\Python37\Lib'에 복사
2. 관리자 권한으로 콘솔 명령창을 실행시킨다.
3. yak.exe와 MalDetecter.dll이 존재하는 폴더에서 파일 실행
    1. `yak.exe -i` :  'explorer.exe'에 MalDetecter.dll을 인젝션한다.
    2. `yak.exe -e` :  인젝션 한 'MalDetecter.dll'을 이젝션한다.

---

### 해결해야할 문제점 및 업데이트

- ~~(11/17) 리턴값이 재대로 출력이 안되는 문제점이 생김~~
- (11/17) whitelist 기능 추가

---

- ~~(11/16) 오류 문제: **generic_type type "Object" is already registered**~~
    - lief 임포트시 오류 메시지 발생
    - numpy와 같이 임포트시 1번은 제대로 작동
    - sys.exit()로 문제 해결
        - 리턴값이 재대로 출력이 안되는 문제점이 생김
- ~~(11/06)메모리 추출 완료~~
	- ~~PE헤더에서 구조체를 사용해 원하는 값을 추출 가능~~
---

- (11/12) 구조체를 이용해 특정 값을 Python에게 넘기는게 가능
    1. ~~(부모 프로세스에서 함) 자식 프로세스에서 되게 전면적인 수정이 필요~~
        - (11/14) 파일에서 읽는 것으로 해결
    2. ~~파이썬은 lief를 사용하기에  '바이너리 데이터'를 넘기는 방식이  필요함~~
        - 아니면 값을 하나하나 비교하는 코드를 다시 작성해야함
        - (11/14) 파일에서 읽는 것으로 해결
    3. ~~ip, url, api 목록 등을 검사할려면, '.text' 섹션이 전부 필요함~~
        - text 섹션을 덤프(변수에 담기) 방법을 모르겠음
            - (11/14) malloc()를 이용해 데이터 담기
            - (11/14) memcpy 등으로 복사
    4. ~~처음에는 됬는데, 현제 c에서 파이썬 모듈 호출이 안됨~~
        1. lief를 임포트를 못함(.pyd 파일을 못 불러옴)
        2. 모듈 사용시 케라스를 사용함으로 c에이전트를 포기해야 할지도 모름
    5. 문제를 찾기위한 디버깅의 어려움
        - (11/15)  python에서 메시지박스를 띄움

---

- (11/06)메모리 추출 완료
    - PE헤더에서 구조체를 사용해 원하는 값을 추출 가능
    - 섹션에 접근에 데이터 덤프 (80%) (테스트 필요)
- (11/06)ASLR  때문에 원하는 주소를 찾는 방법이 필요함!

---

- explorer.exe 로그인후 후킹은 가능, 로그인 전인 서비스 같은것도 후킹 가능하게?
- ~~실행 중인 상태인 프로세스 중지시 , 부모 프로세스가 종료됨~~
    - (11/01) 수정 : 프로세스를 점검하고 종료 시키는 루틴의 적용 시점을 변경함(필요없는 부분에서 루틴이 돌지 않게함)
- PE 구조 파싱
    - 파일에서 파싱은 가능하나, 메모리에서 파싱이 문제
- C언어와 Python 합치기
    - C언어에 python 코드 불러오기로 방향을 선정
- 화이트리스트 기능
- (11/01) 추가 : 프로세스를 종료하기 전에 메시지박스를 출력해 '종료 여부' 확인 가능
- (11/02) 문제 : 후킹 타이밍 확인 필요
    - ~~데이터가 메모리에 올라간 상태에서 후킹이 필요~~ (해결)
    - volatility malfind 의 작동구조를 확인하여, 메모리 덤프/추출 하기 구현?
