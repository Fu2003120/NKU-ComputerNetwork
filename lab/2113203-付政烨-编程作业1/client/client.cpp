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
bool isRunning = true; // 用于控制程序的运行状态

void SendToServer() {
    char buffer[BUFFER_SIZE];
    while (isRunning)
    {
        cout << ">> ";
        cin >> buffer;
        if (cin.eof()) {
            isRunning = false; // 如果用户按下Ctrl+Z，修改程序运行状态为false
            cout << "程序已终止." << endl; // 打印终止信息
            break;
        }
        send(serverSocket, buffer, strlen(buffer), 0);
    }
}

int main()
{
    initgraph(300, 400, SHOWCONSOLE); //聊天窗口
    int displayPosition = 0; //聊天窗口当前显示位置
    HWND hWnd = GetHWnd(); // 获取当前窗口句柄
    SetWindowText(hWnd, TEXT("chat")); // 设置窗口标题为 "chat"

    // 1.确定网络协议版本
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cout << "初始化网络协议版本失败！错误码：" << GetLastError() << endl;
        return -1;
    }
    cout << "初始化网络协议版本成功！\n";

    // 2.创建socket
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == SOCKET_ERROR) {
        cout << "创建Socket失败！错误码：" << GetLastError() << endl;
        WSACleanup(); // 清理版本信息
        return -1;
    }
    cout << "创建Socket成功！\n";

    // 3.确定服务器协议地址簇
    SOCKADDR_IN serverAddress = { 0 };
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);
    serverAddress.sin_port = htons(SERVER_PORT);

    // 4.连接服务器
    int Flag = connect(serverSocket, (sockaddr*)&serverAddress, sizeof serverAddress);
    if (Flag == -1) {
        cout << "连接服务器失败！错误码：" << GetLastError() << endl;
        closesocket(serverSocket); //关闭socket
        WSACleanup(); //清理版本信息
        return -1;
    }
    cout << "连接服务器成功！（按下`Ctrl+Z`退出程序）\n";

    // 5.通信：创建线程发送数据
    CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SendToServer, NULL, NULL, NULL);

    // 6.接收数据
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
            cout << "与服务器的连接已断开." << endl;
            isRunning = false; // 如果与服务器的连接断开，修改程序运行状态为false
            break;
        }
    }

    // 8.关闭socket
    closesocket(serverSocket);

    // 9.清理协议版本信息
    WSACleanup();

    return 0;
}
