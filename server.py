from socket import *

HOST='' #호스트를 지정하지 않으면 가능한 모든 인터페이스를 의미한다.
port = 8080
list_1 = []

while True:
    serverSock = socket(AF_INET, SOCK_STREAM)
    serverSock.bind((HOST, port))
    serverSock.listen(1)

    print('%d번 포트로 접속 대기중...'%port)

    connectionSock, addr = serverSock.accept()

    print(str(addr), '에서 접속되었습니다.')

    while True:
        data=connectionSock.recv(1024)
        if not data: break
        connectionSock.send(data) #받은 데이터를 그대로 클라이언트에 전송
    connectionSock.close()
    print(str(addr), '의 접속이 끊겼습니다.')
    
    

##while True:
##    sendData = input('>>>')
##    connectionSock.send(sendData.encode('utf-8'))
##
##    recvData = connectionSock.recv(1024)
##    print('상대방 :', recvData.decode('utf-8'))
