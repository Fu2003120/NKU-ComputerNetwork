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
bool isRunning = true; // 定义一个全局变量用于控制服务器是否在运行

// 全局定义互斥锁
HANDLE clientMutex;

// 封装通讯操作
void HandleClientMessages(int clientId) {
    int receivedBytes;
    char buffer[BUFFER_SIZE];
    char formattedMsg[FORMATTEDMSG_SIZE];

    // 发送用户加入的通知
    snprintf(formattedMsg, FORMATTEDMSG_SIZE, "用户[%d] 已加入聊天。", clientId);
    for (int i = 0; i < clientCount; i++) {
        if (i != clientId) { // 不发送给自己
            send(clientSockets[i], formattedMsg, strlen(formattedMsg), NULL);
        }
    }

    while (isRunning) {
        // 从特定的客户端套接字接收数据，并将接收到的数据存储在 buffer 中。
        receivedBytes = recv(clientSockets[clientId], buffer, BUFFER_SIZE - 1, NULL);
        if (receivedBytes > 0) {
            buffer[receivedBytes] = 0; // 添加结束符

            // 获取当前时间
            auto current_time = chrono::system_clock::now();
            time_t tt = chrono::system_clock::to_time_t(current_time);
            struct tm* ptm = localtime(&tt);
            char timeString[32];
            strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", ptm);

            // 格式化信息以包含时间
            memset(formattedMsg, 0, FORMATTEDMSG_SIZE);
            snprintf(formattedMsg, FORMATTEDMSG_SIZE, "[%s] 用户[%d]: %s", timeString, clientId, buffer);

            // 向所有客户端发送格式化后的信息
            for (int i = 0; i < clientCount; i++) {
                send(clientSockets[i], formattedMsg, strlen(formattedMsg), NULL);
            }
        }
        else if (receivedBytes == 0 || receivedBytes == SOCKET_ERROR) {
            // 客户端已断开连接
            snprintf(formattedMsg, FORMATTEDMSG_SIZE, "用户[%d] 已离开聊天", clientId);
            for (int i = 0; i < clientCount; i++) {
                if (i != clientId) { // 不发送给自己
                    send(clientSockets[i], formattedMsg, strlen(formattedMsg), NULL);
                }
            }
            cout << formattedMsg << endl;  // 打印用户离开的信息到服务器控制台
            break; // 跳出循环
        }
    }
}


// 用于捕获用户的输入
DWORD WINAPI InputThread(LPVOID param) {
    char input;
    while (true) {
        cin >> input;
        if (cin.eof()) {  // 检查EOF标记
            isRunning = false;
            cout << "服务端已终止" << endl;
            break;
        }
    }
    return 0;
}


int main() {
    // 0.初始化互斥对象
    clientMutex = CreateMutex(NULL, FALSE, NULL);
    if (clientMutex == NULL) {
        cout << "创建互斥对象失败！错误码: " << GetLastError() << endl;
        return -1;
    }

    // 1.确定网络协议版本
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cout << "初始化WinSock失败！错误码: " << WSAGetLastError() << endl;
        return -1;
    }
    cout << "初始化WinSock成功！\n";

    // 2.创建socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == SOCKET_ERROR) {
        cout << "创建Socket失败！错误码: " << WSAGetLastError() << endl;
        WSACleanup(); //清理版本信息
        return -1;
    }
    cout << "创建Socket成功！\n";

    // 3.确定服务器协议地址簇
    SOCKADDR_IN serverAddr = { 0 };
    serverAddr.sin_family = AF_INET; // IPV4
    serverAddr.sin_addr.S_un.S_addr = inet_addr(SERVER_IP); //IP地址
    serverAddr.sin_port = htons(SERVER_PORT); //端口号

    // 4.绑定：bind函数用于绑定一个套接字到一个IP地址和端口号。这是为了指定套接字应该监听来自哪个网络地址的连接请求。
    int Flag = bind(serverSocket, (sockaddr*)&serverAddr, sizeof serverAddr);
    if (Flag == -1) {
        cout << "绑定失败！错误码: " << WSAGetLastError() << endl;
        closesocket(serverSocket); //关闭socket
        WSACleanup(); //清理版本信息
        return -1;
    }
    cout << "绑定成功！\n";

    // 5.监听：开始监听serverSocket上的连接，并允许最多10个客户端的连接在队列中等待被接受。简而言之，listen函数告诉操作系统该套接字准备好接受来自客户端的连接了。
    Flag = listen(serverSocket, 10);
    if (Flag == -1) {
        cout << "监听失败！错误码: " << WSAGetLastError() << endl;
        closesocket(serverSocket); //关闭socket
        WSACleanup(); //清理版本信息
        return -1;
    }
    cout << "开始监听客户端连接...（按下`Ctrl+Z`退出程序）\n";

    CreateThread(NULL, 0, InputThread, NULL, 0, NULL); // 创建一个新线程来捕获用户输入

    // 6.接受客户端连接
    while (isRunning && clientCount < MAX_CLIENTS) {
        // 从 serverSocket 接受一个客户端的连接请求，并获取该客户端的地址信息。返回的新套接字 acceptedSocket 可以用于与这个特定的客户端通信。
        SOCKADDR_IN clientAddress = { 0 };
        int len = sizeof(clientAddress);
        SOCKET acceptedSocket = accept(serverSocket, (sockaddr*)&clientAddress, &len);

        if (acceptedSocket == SOCKET_ERROR) {
            cout << "接受客户端连接失败！错误码: " << WSAGetLastError() << endl;
            continue;
        }

        WaitForSingleObject(clientMutex, INFINITE); // 获取互斥锁

        clientSockets[clientCount] = acceptedSocket; // 不加互斥锁，多个客户端同时申请会异常
        char* clientIP = inet_ntoa(clientAddress.sin_addr);
        cout << "接受到来自 " << clientIP << " 的连接请求" << endl;
        cout << "用户[" << clientCount << "] 已加入聊天\n";
        clientCount++; // 不加互斥锁，多个客户端同时申请会异常

        ReleaseMutex(clientMutex); // 释放当前线程拥有的互斥锁

        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)HandleClientMessages, (LPVOID)(clientCount - 1), NULL, NULL);
    }

    for (int i = 0; i < clientCount; i++) {
        closesocket(clientSockets[i]);
    }

    // 8.关闭socket
    closesocket(serverSocket);

    // 9.清理协议版本信息
    WSACleanup();

    return 0;
}

