#include<iostream>
#include<WinSock2.h>
#include<Windows.h>
#include <cstring>
#include <chrono>
#include <ctime>
#pragma comment(lib,"ws2_32.lib")

using namespace std;

const int MAX_CLIENTS = 1024;
const int BUFFER_SIZE = 60;
const int FORMATTEDMSG_SIZE = 80;
const char* SERVER_IP = "127.0.0.1";
const int SERVER_PORT = 9527;

SOCKET clientSockets[MAX_CLIENTS];
int clientCount = 0;
bool isRunning = true; // ����һ��ȫ�ֱ������ڿ��Ʒ������Ƿ�������

// ȫ�ֶ��廥����
HANDLE clientMutex;

// ��װͨѶ����
void HandleClientMessages(int clientId) {
    int receivedBytes;
    char buffer[BUFFER_SIZE];
    char formattedMsg[FORMATTEDMSG_SIZE];

    // �����û������֪ͨ
    snprintf(formattedMsg, FORMATTEDMSG_SIZE, "�û�[%d] �Ѽ������졣", clientId);
    for (int i = 0; i < clientCount; i++) {
        if (i != clientId) { // �����͸��Լ�
            send(clientSockets[i], formattedMsg, strlen(formattedMsg), NULL);
        }
    }

    while (isRunning) {
        // ���ض��Ŀͻ����׽��ֽ������ݣ��������յ������ݴ洢�� buffer �С�
        receivedBytes = recv(clientSockets[clientId], buffer, BUFFER_SIZE - 1, NULL);
        if (receivedBytes > 0) {
            buffer[receivedBytes] = 0; // ��ӽ�����

            // ��ȡ��ǰʱ��
            auto current_time = chrono::system_clock::now();
            time_t tt = chrono::system_clock::to_time_t(current_time);
            struct tm* ptm = localtime(&tt);
            char timeString[32];
            strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", ptm);

            // ��ʽ����Ϣ�԰���ʱ��
            memset(formattedMsg, 0, FORMATTEDMSG_SIZE);
            snprintf(formattedMsg, FORMATTEDMSG_SIZE, "[%s] �û�[%d]: %s", timeString, clientId, buffer);

            // �����пͻ��˷��͸�ʽ�������Ϣ
            for (int i = 0; i < clientCount; i++) {
                send(clientSockets[i], formattedMsg, strlen(formattedMsg), NULL);
            }
        }
        else if (receivedBytes == 0 || receivedBytes == SOCKET_ERROR) {
            // �ͻ����ѶϿ�����
            snprintf(formattedMsg, FORMATTEDMSG_SIZE, "�û�[%d] ���뿪����", clientId);
            for (int i = 0; i < clientCount; i++) {
                if (i != clientId) { // �����͸��Լ�
                    send(clientSockets[i], formattedMsg, strlen(formattedMsg), NULL);
                }
            }
            cout << formattedMsg << endl;  // ��ӡ�û��뿪����Ϣ������������̨
            break; // ����ѭ��
        }
    }
}


// ���ڲ����û�������
DWORD WINAPI InputThread(LPVOID param) {
    char input;
    while (true) {
        cin >> input;
        if (cin.eof()) {  // ���EOF���
            isRunning = false;
            cout << "���������ֹ" << endl;
            break;
        }
    }
    return 0;
}


int main() {
    // 0.��ʼ���������
    clientMutex = CreateMutex(NULL, FALSE, NULL);
    if (clientMutex == NULL) {
        cout << "�����������ʧ�ܣ�������: " << GetLastError() << endl;
        return -1;
    }

    // 1.ȷ������Э��汾
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cout << "��ʼ��WinSockʧ�ܣ�������: " << WSAGetLastError() << endl;
        return -1;
    }
    cout << "��ʼ��WinSock�ɹ���\n";

    // 2.����socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == SOCKET_ERROR) {
        cout << "����Socketʧ�ܣ�������: " << WSAGetLastError() << endl;
        WSACleanup(); //����汾��Ϣ
        return -1;
    }
    cout << "����Socket�ɹ���\n";

    // 3.ȷ��������Э���ַ��
    SOCKADDR_IN serverAddr = { 0 };
    serverAddr.sin_family = AF_INET; // IPV4
    serverAddr.sin_addr.S_un.S_addr = inet_addr(SERVER_IP); //IP��ַ
    serverAddr.sin_port = htons(SERVER_PORT); //�˿ں�

    // 4.�󶨣�bind�������ڰ�һ���׽��ֵ�һ��IP��ַ�Ͷ˿ںš�����Ϊ��ָ���׽���Ӧ�ü��������ĸ������ַ����������
    int Flag = bind(serverSocket, (sockaddr*)&serverAddr, sizeof serverAddr);
    if (Flag == -1) {
        cout << "��ʧ�ܣ�������: " << WSAGetLastError() << endl;
        closesocket(serverSocket); //�ر�socket
        WSACleanup(); //����汾��Ϣ
        return -1;
    }
    cout << "�󶨳ɹ���\n";

    // 5.��������ʼ����serverSocket�ϵ����ӣ����������10���ͻ��˵������ڶ����еȴ������ܡ������֮��listen�������߲���ϵͳ���׽���׼���ý������Կͻ��˵������ˡ�
    Flag = listen(serverSocket, 10);
    if (Flag == -1) {
        cout << "����ʧ�ܣ�������: " << WSAGetLastError() << endl;
        closesocket(serverSocket); //�ر�socket
        WSACleanup(); //����汾��Ϣ
        return -1;
    }
    cout << "��ʼ�����ͻ�������...������`Ctrl+Z`�˳�����\n";

    CreateThread(NULL, 0, InputThread, NULL, 0, NULL); // ����һ�����߳��������û�����

    // 6.���ܿͻ�������
    while (isRunning && clientCount < MAX_CLIENTS) {
        // �� serverSocket ����һ���ͻ��˵��������󣬲���ȡ�ÿͻ��˵ĵ�ַ��Ϣ�����ص����׽��� acceptedSocket ��������������ض��Ŀͻ���ͨ�š�
        SOCKADDR_IN clientAddress = { 0 };
        int len = sizeof(clientAddress);
        SOCKET acceptedSocket = accept(serverSocket, (sockaddr*)&clientAddress, &len);

        if (acceptedSocket == SOCKET_ERROR) {
            cout << "���ܿͻ�������ʧ�ܣ�������: " << WSAGetLastError() << endl;
            continue;
        }

        WaitForSingleObject(clientMutex, INFINITE); // ��ȡ������

        clientSockets[clientCount] = acceptedSocket; // ���ӻ�����������ͻ���ͬʱ������쳣
        char* clientIP = inet_ntoa(clientAddress.sin_addr);
        cout << "���ܵ����� " << clientIP << " ����������" << endl;
        cout << "�û�[" << clientCount << "] �Ѽ�������\n";
        clientCount++; // ���ӻ�����������ͻ���ͬʱ������쳣

        ReleaseMutex(clientMutex); // �ͷŵ�ǰ�߳�ӵ�еĻ�����

        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)HandleClientMessages, (LPVOID)(clientCount - 1), NULL, NULL);
    }

    for (int i = 0; i < clientCount; i++) {
        closesocket(clientSockets[i]);
    }

    // 8.�ر�socket
    closesocket(serverSocket);

    // 9.����Э��汾��Ϣ
    WSACleanup();

    return 0;
}

