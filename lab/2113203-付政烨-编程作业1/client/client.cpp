#include<iostream>
#include<WinSock2.h>
#include<Windows.h>
#include<graphics.h>
#pragma comment(lib,"ws2_32.lib")

using namespace std;

const char* SERVER_IP = "127.0.0.1";
const int SERVER_PORT = 9527;
const int BUFFER_SIZE = 60;

SOCKET serverSocket;
bool isRunning = true; // ���ڿ��Ƴ��������״̬

void SendToServer() {
    char buffer[BUFFER_SIZE];
    while (isRunning)
    {
        cout << ">> ";
        cin >> buffer;
        if (cin.eof()) {
            isRunning = false; // ����û�����Ctrl+Z���޸ĳ�������״̬Ϊfalse
            cout << "��������ֹ." << endl; // ��ӡ��ֹ��Ϣ
            break;
        }
        send(serverSocket, buffer, strlen(buffer), 0);
    }
}

int main()
{
    initgraph(300, 400, SHOWCONSOLE); //���촰��
    int displayPosition = 0; //���촰�ڵ�ǰ��ʾλ��
    HWND hWnd = GetHWnd(); // ��ȡ��ǰ���ھ��
    SetWindowText(hWnd, TEXT("chat")); // ���ô��ڱ���Ϊ "chat"

    // 1.ȷ������Э��汾
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cout << "��ʼ������Э��汾ʧ�ܣ������룺" << GetLastError() << endl;
        return -1;
    }
    cout << "��ʼ������Э��汾�ɹ���\n";

    // 2.����socket
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == SOCKET_ERROR) {
        cout << "����Socketʧ�ܣ������룺" << GetLastError() << endl;
        WSACleanup(); // ����汾��Ϣ
        return -1;
    }
    cout << "����Socket�ɹ���\n";

    // 3.ȷ��������Э���ַ��
    SOCKADDR_IN serverAddress = { 0 };
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);
    serverAddress.sin_port = htons(SERVER_PORT);

    // 4.���ӷ�����
    int Flag = connect(serverSocket, (sockaddr*)&serverAddress, sizeof serverAddress);
    if (Flag == -1) {
        cout << "���ӷ�����ʧ�ܣ������룺" << GetLastError() << endl;
        closesocket(serverSocket); //�ر�socket
        WSACleanup(); //����汾��Ϣ
        return -1;
    }
    cout << "���ӷ������ɹ���������`Ctrl+Z`�˳�����\n";

    // 5.ͨ�ţ������̷߳�������
    CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SendToServer, NULL, NULL, NULL);

    // 6.��������
    char recvBuffer[BUFFER_SIZE];
    while (isRunning)
    {
        Flag = recv(serverSocket, recvBuffer, BUFFER_SIZE - 1, NULL);
        if (Flag > 0) {
            recvBuffer[Flag] = 0;
            outtextxy(1, displayPosition * 20, recvBuffer);
            displayPosition++;
        }
        else if (Flag == 0 || Flag == SOCKET_ERROR) {
            cout << "��������������ѶϿ�." << endl;
            isRunning = false; // ���������������ӶϿ����޸ĳ�������״̬Ϊfalse
            break;
        }
    }

    // 8.�ر�socket
    closesocket(serverSocket);

    // 9.����Э��汾��Ϣ
    WSACleanup();

    return 0;
}
