#include <WinSock2.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string.h>
#include <string>
#include <fstream>
#include <chrono>
#include <sys/types.h>
#include <random>
#include <thread>
#pragma comment(lib, "ws2_32.lib")

using namespace std;

#define PORT 8888
#define IP "127.0.0.1"
#define DEFAULT_BUFFER_SIZE  4096
#define DEFAULT_WindowSize_SIZE  32
#define RESEND_TNTERVAL  1
#define MAX_RETRY_COUNT 8

#define PACKET_DELAY_MS 0
#define LOSS_RATE  0
const BYTE SYN = 0x1;		//SYN = 1 ACK = 0 FIN = 0
const BYTE ACK = 0x2;		//SYN = 0 ACK = 1 FIN = 0
const BYTE ACK_SYN = 0x3;	//SYN = 1 ACK = 1 FIN = 0
const BYTE FIN = 0x4;		//FIN = 1 ACK = 0 SYN = 0
const BYTE FIN_ACK = 0x6;	//FIN = 1 ACK = 1 SYN = 0
const BYTE OVER = 0x8;		//结束标志
const BYTE END = 0x16;		//全局结束标志

// 随机数生成器的初始化
random_device rd;
mt19937 gen(rd());
uniform_int_distribution<> dis(0, 99);

bool shouldDropPacket() {
    return dis(gen) < (LOSS_RATE * 100);
}

struct Packet_Header
{
    WORD datasize;		// 数据长度
    BYTE tag;			// 标签
    //八位，使用后四位，排列是OVER FIN ACK SYN 
    BYTE WindowSize;		// 窗口大小
    BYTE seq;			// 序列号
    BYTE seq_quotient;	// 序列号（商）
    BYTE ack;			// 确认号
    WORD checksum;		// 校验和

    // 初始化
    Packet_Header()
    {
        datasize = 0;
        tag = 0;
        WindowSize = 0;
        seq = 0;
        seq_quotient = 0;
        ack = 0;
        checksum = 0;
    }
};

// 计算校验和的函数
WORD compute_sum(WORD* message, int size) {
    // size = 8
    // 计算处理的WORD数量，如果size是奇数，则加1，确保处理所有字节
    int count = (size + 1) / 2;

    // 分配足够的内存来存储消息副本并为可能的额外字节留出空间
    WORD* buf = (WORD*)malloc(size + 1);
    // 初始化分配的内存，确保最后一个字节（如果有）被设置为0
    memset(buf, 0, size + 1);
    // 将原始消息复制到新分配的缓冲区中
    memcpy(buf, message, size);

    u_long sum = 0; // 用于累加校验和的变量
    while (count--) {
        sum += *buf++; // 将消息中的每个WORD加到sum中
        if (sum & 0xffff0000) { // 溢出
            sum &= 0xffff; // 保留低16位
            sum++; // 回滚
        }
    }
    return ~(sum & 0xffff); // 取反sum的低16位并返回，得到最终的校验和
}

// 客户端与服务端建立连接（采取三次握手的方式）
// 参数：socketServer - 服务端套接字，clieAddr - 客户端地址，clieAddrlen - 客户端地址长度
int Client_Server_Connect(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen) {
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet)]);  // 使用智能指针自动管理内存

    try {
        // 第一次握手：服务端等待并接收客户端发送的SYN包
        while (true) {
            if (recvfrom(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, &clieAddrlen) == -1) {
                throw runtime_error("无法接收客户端发送的连接请求，错误码：" + to_string(WSAGetLastError()));
            }
            memcpy(&packet, buffer.get(), sizeof(packet));
            if (packet.tag == SYN && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
                cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
                cout << "\033[32m" << "| 成功接收第一次握手信息 |" << "\033[0m" << endl;
                break;
            }
        }

        // Jacobson/Karels算法
        // 初始化RTT相关参数，用于后续的超时计算
        double estimatedRTT = 1.0;  // 初始估计RTT
        double devRTT = 0.0;  // 初始RTT偏差
        const double alpha = 0.125;  // 估计RTT的权重
        const double beta = 0.25;  // 偏差的权重
        double timeoutDuration = estimatedRTT + 4 * devRTT;  // 初始化超时时间

        // 第二次握手：服务端向客户端发送ACK包，确认收到SYN包
        packet.tag = ACK;
        packet.checksum = 0;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen) == -1) {
            throw runtime_error("发送ACK失败，错误码：" + to_string(WSAGetLastError()));
        }

        // 设置非阻塞模式，用于超时检测
        u_long mode = 1;
        ioctlsocket(socketServer, FIONBIO, &mode);
        clock_t start = clock();  // 记录开始等待ACK_SYN包的时间

        // 第三次握手：服务端等待客户端发送ACK_SYN包
        while (recvfrom(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, &clieAddrlen) <= 0) {
            // 检查是否超时，如果是，则重发ACK包
            if (double(clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                cout << "\033[34m" << "超时，正在重传ACK" << "\033[0m" << endl;
                if (sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen) == -1) {
                    throw runtime_error("重传ACK失败，错误码：" + to_string(WSAGetLastError()));
                }
                start = clock();  // 重置计时器
                timeoutDuration = estimatedRTT + 4 * devRTT;  // 基于RTT的动态调整超时时间
            }
        }

        // 更新RTT估计
        double sampleRTT = double(clock() - start) / CLOCKS_PER_SEC;
        estimatedRTT = (1 - alpha) * estimatedRTT + alpha * sampleRTT;
        devRTT = (1 - beta) * devRTT + beta * abs(sampleRTT - estimatedRTT);
        timeoutDuration = estimatedRTT + 4 * devRTT;  // 更新超时时间

        // 恢复为阻塞模式
        mode = 0;
        ioctlsocket(socketServer, FIONBIO, &mode);

        cout << "\033[32m" << "| 成功发送第二次握手信息 |" << "\033[0m" << endl;

        // 检查接收到的ACK_SYN包是否正确
        memcpy(&packet, buffer.get(), sizeof(packet));
        if (!(packet.tag == ACK_SYN && (compute_sum((WORD*)&packet, sizeof(packet)) == 0))) {
            throw runtime_error("无法接收客户端回传建立可靠连接，错误码：" + to_string(WSAGetLastError()));
        }
        cout << "\033[32m" << "| 成功接收第三次握手信息 |" << "\033[0m" << endl;
        cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
    }
    catch (const runtime_error& e) {
        cout << "\033[31m" << "异常发生: " << e.what() << "\033[0m" << endl;
        return -1;
    }

    return int(packet.datasize);  // 返回数据包大小
}

// 客户端与服务端断开连接（采取四次挥手的方式）
// 参数：socketServer - 服务端套接字，clieAddr - 客户端地址，clieAddrlen - 客户端地址长度
int Client_Server_Disconnect(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen) {
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet)]);  // 使用智能指针自动管理内存

    try {
        // 接收客户端发来的第一次挥手信息（FIN_ACK）
        while (true) {
            // 接收数据包
            if (recvfrom(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, &clieAddrlen) == -1) {
                throw runtime_error("无法接收客户端发送的挥手请求，错误码：" + to_string(WSAGetLastError()));
            }

            // 检查是否为FIN_ACK标志的数据包
            memcpy(&packet, buffer.get(), sizeof(packet));
            if (packet.tag == FIN_ACK && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
                cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
                cout << "\033[32m" << "| 成功接收第一次挥手信息 |" << "\033[0m" << endl;
                break;
            }
        }

        // 第二次：服务端向客户端发送挥手信息（ACK）
        packet.tag = ACK;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen) == -1) {
            throw runtime_error("服务端发送ACK失败，错误码：" + to_string(WSAGetLastError()));
        }
        cout << "\033[32m" << "| 成功发送第二次挥手信息 |" << "\033[0m" << endl;

        // 服务端处理未发送完的数据（如果有的话）

        // 第三次：服务端向客户端发送挥手信息（FIN_ACK）
        packet.tag = FIN_ACK;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen) == -1) {
            throw runtime_error("服务端发送FIN_ACK失败，错误码：" + to_string(WSAGetLastError()));
        }
        cout << "\033[32m" << "| 成功发送第三次挥手信息 |" << "\033[0m" << endl;

        clock_t start = clock();  // 记录发送时间
        int retryCount = 0;       // 重传计数
        int timeoutDuration = 1;  // 初始超时时间为1秒

        // 第四次挥手：服务端接收客户端发送的ACK
        while (true)
        {
            if (recvfrom(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, &clieAddrlen) <= 0) {
                // 如果超时，则可能需要重传FIN_ACK
                if ((clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                    retryCount++;
                    if (retryCount > MAX_RETRY_COUNT) {
                        throw runtime_error("第四次挥手重传次数超过限制，错误码：" + to_string(WSAGetLastError()));
                    }
                    cout << "\033[34m" << "等待第三次挥手超时，正在进行第 " << retryCount << " 次重传" << "\033[0m" << endl;
                    start = clock(); // 重置计时器
                    timeoutDuration *= 2; // 指数退避
                }
            }
            else
            {
                cout << "\033[32m" << "| 成功接收第四次挥手信息 |" << "\033[0m" << endl;
                cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
                cout << "\033[32m" << "客户端与服务端成功断开连接！" << "\033[0m" << endl;
                break;
            }
        }
    }
    catch (const runtime_error& e) {
        cout << "\033[31m" << "断开连接过程中发生异常: " << e.what() << "\033[0m" << endl;
        return -1;
    }

    return 1;
}

// 发送端
void SendMessage(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, char* Message, int mes_size, int MAX_SIZE, int WindowSizeSize) {
    Packet_Header packet;
    int totalPacketNum = mes_size / MAX_SIZE + (mes_size % MAX_SIZE != 0);
    int base = 0;           // 窗口基序号
    int nextSeqNum = 0;     // 分组序列号

    // 初始化发送缓冲区
    char** stagingBuffer = new(nothrow) char* [WindowSizeSize];
    int* stagingBufferLengths = new(nothrow) int[WindowSizeSize];
    for (int i = 0; i < WindowSizeSize; i++) {
        stagingBuffer[i] = new(nothrow) char[sizeof(packet) + MAX_SIZE];
    }

    // 初始化分组确认状态和定时器
    bool* ackReceived = new(nothrow) bool[WindowSizeSize];
    clock_t* packetTimers = new(nothrow) clock_t[WindowSizeSize];
    bool* timerRunning = new(nothrow) bool[WindowSizeSize];
    for (int i = 0; i < WindowSizeSize; i++) {
        ackReceived[i] = false;
        timerRunning[i] = false;
    }

    // 设置为非阻塞模式
    u_long socketMode = 1;
    ioctlsocket(socketClient, FIONBIO, &socketMode);

    // 发送分组
    while (base < totalPacketNum) {
        // 发送窗口内的分组
        while (nextSeqNum < base + WindowSizeSize && nextSeqNum < totalPacketNum) {
            // 计算分组大小
            int packetDataSize = (nextSeqNum == totalPacketNum - 1) ? mes_size - (totalPacketNum - 1) * MAX_SIZE : MAX_SIZE;

            // 设置分组头部信息
            packet.tag = 0;
            packet.seq = nextSeqNum % 256;
            packet.seq_quotient = nextSeqNum / 256;                 // 用于接收端恢复实际的序列号
            packet.datasize = packetDataSize;
            packet.WindowSize = WindowSizeSize - (nextSeqNum - base);   // 当前窗口中还可以发送的分组数量
            packet.checksum = 0;
            packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));

            // 复制分组到发送缓冲区
            memcpy(stagingBuffer[nextSeqNum % WindowSizeSize], &packet, sizeof(packet));
            char* messageFragment = Message + nextSeqNum * MAX_SIZE;
            memcpy(stagingBuffer[nextSeqNum % WindowSizeSize] + sizeof(packet), messageFragment, packetDataSize);
            stagingBufferLengths[nextSeqNum % WindowSizeSize] = packetDataSize;
            sendto(socketClient, stagingBuffer[nextSeqNum % WindowSizeSize], sizeof(packet) + packetDataSize, 0, (sockaddr*)&servAddr, servAddrlen);
            cout << "\033[33m[SEND]\033[0m 发送分组 - 序列号: " << nextSeqNum << "，packet序列号: " << int(packet.seq) << ", 校验和: " << int(packet.checksum) << "" << endl;

            // 启动或重置定时器,并且针对每个发送的分组独立地跟踪其超时状态
            packetTimers[nextSeqNum % WindowSizeSize] = clock();
            timerRunning[nextSeqNum % WindowSizeSize] = true;

            nextSeqNum++;
        }

        char receiveBuffer[sizeof(packet)];

        // 重传分组
        while (recvfrom(socketClient, receiveBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
            // 遍历所有已发送但尚未收到ACK确认的分组
            for (int i = base; i < nextSeqNum; i++) {
                if (!ackReceived[i % WindowSizeSize] && (clock() - packetTimers[i % WindowSizeSize]) / CLOCKS_PER_SEC > RESEND_TNTERVAL) {
                    sendto(socketClient, stagingBuffer[i % WindowSizeSize], sizeof(packet) + stagingBufferLengths[i % WindowSizeSize], 0, (sockaddr*)&servAddr, servAddrlen);
                    cout << "\033[31m[WARNING]\033[0m 没有接收到ack，触发超时 - 重传分组，未确认包编号：" << i << endl;
                    packetTimers[i % WindowSizeSize] = clock();
                }
            }
        }

        // 处理接收到的确认信息
        memcpy(&packet, receiveBuffer, sizeof(packet));

        // 校验分组
        if ((compute_sum((WORD*)&packet, sizeof(packet)) != 0)) {
            cout << "\033[31m[ERROR]\033[0m 接收到的ACK包校验失败，校验和：" << int(packet.checksum) << endl;
            continue;
        }

        // 成功收到ACK
        int packetIndex = int(packet.ack) % WindowSizeSize;

        // 检查是否重复接收
        if (!ackReceived[packetIndex]) {
            // 更新接收标记和定时器
            ackReceived[packetIndex] = true;
            timerRunning[packetIndex] = false;
            cout << "\033[32m[ACC]\033[0m 收到确认 - ACK: " << int(packet.ack) << "，对应窗口索引: " << packetIndex << endl;

            // 滑动窗口
            while (ackReceived[base % WindowSizeSize] && base < nextSeqNum) {
                // 重置窗口滑动后新位置的ackReceived状态
                ackReceived[base % WindowSizeSize] = false;
                timerRunning[base % WindowSizeSize] = false;
                base++;
                cout << "\033[35m[MOVING]\033[0m 收到顺序到来的确认号 - 窗口滑动 - 从 " << base << " 到 " << base + WindowSizeSize << endl;
            }
        }
        else {
            cout << "\033[33m[WARNING]\033[0m 收到重复确认 ACK: " << int(packet.ack) << endl;
        }
    }

    // 发送结束标志
    packet.tag = OVER;
    char* endSignalBuffer = new char[sizeof(packet)];
    packet.checksum = 0;
    packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
    memcpy(endSignalBuffer, &packet, sizeof(packet));
    sendto(socketClient, endSignalBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
    cout << "\033[33m[SEND]\033[0m 结束标志已发送" << endl;

    // 确认结束标志的接收
    clock_t endSignalStartTime = clock();
    while (recvfrom(socketClient, endSignalBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
        if ((clock() - endSignalStartTime) / CLOCKS_PER_SEC > RESEND_TNTERVAL) {
            sendto(socketClient, endSignalBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
            cout << "\033[31m[WARNING]\033[0m 结束标志发送超时 - 正在重传" << endl;
            endSignalStartTime = clock();
        }
    }

    // 切换回阻塞模式
    socketMode = 0;
    ioctlsocket(socketClient, FIONBIO, &socketMode);

    memcpy(&packet, endSignalBuffer, sizeof(packet));
    if (packet.tag == OVER && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
        cout << "\033[32m[ACC]\033[0m 成功接收到结束标志" << endl;
    }
    else {
        cout << "\033[31m[WARNING]\033[0m  无法接收客户端回传的结束标志" << endl;
    }

    // 清理资源
    delete[] ackReceived;
    delete[] packetTimers;
    delete[] timerRunning;
    for (int i = 0; i < WindowSizeSize; i++) {
        delete[] stagingBuffer[i];
    }
    delete[] stagingBuffer;
    delete[] stagingBufferLengths;

}

// 接收端
int RecvMessage(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen, char* Message, int MAX_SIZE, int WindowSizeSize) {
    Packet_Header packet;
    char* receiveBuffer = new (nothrow) char[sizeof(packet) + MAX_SIZE];
    int rcv_base = 0;               // 窗口基序号
    long totalDataLength = 0;       // 已接收的数据总长度

    // 初始化接收端缓冲区和标记数组
    char** packetBuffer = new char* [2 * WindowSizeSize];  // 修改为2N大小的缓冲区
    bool* isReceived = new bool[2 * WindowSizeSize];
    for (int i = 0; i < 2 * WindowSizeSize; ++i) {
        packetBuffer[i] = new char[sizeof(packet) + MAX_SIZE];
        isReceived[i] = false;
    }

    while (true) {
        while (recvfrom(socketServer, receiveBuffer, sizeof(packet) + MAX_SIZE, 0, (sockaddr*)&clieAddr, &clieAddrlen) <= 0);

        memcpy(&packet, receiveBuffer, sizeof(packet));

        // 处理全局结束标记
        if (packet.tag == END && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            cout << "\033[32m[ACC]\033[0m 全局结束标志已接收" << endl;
            return 999;
        }

        // 处理单次数据包发送结束标记
        if (packet.tag == OVER && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            cout << "\033[32m[ACC]\033[0m 结束标志已接收" << endl;
            break;
        }

        // 校验数据包
        if (packet.tag == 0 && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            int seqNum = int(packet.seq) + int(packet.seq_quotient) * 256;
            int bufferIndex = seqNum % (2 * WindowSizeSize);  // 索引适应2N大小的缓冲区
            Packet_Header ackPacket;
            // 检查序列号是否在2倍窗口范围内
            bool isInDoubleWindowSizeSize = (seqNum >= rcv_base - WindowSizeSize) && (seqNum < rcv_base + WindowSizeSize);

            if (isInDoubleWindowSizeSize) {
                // 发送ACK，即使数据包不在当前接收窗口内

                ackPacket.tag = 0;
                ackPacket.ack = seqNum;
                ackPacket.checksum = 0;
                ackPacket.checksum = compute_sum((WORD*)&ackPacket, sizeof(ackPacket));
                memcpy(receiveBuffer, &ackPacket, sizeof(ackPacket));

                // 判断是否应该丢包
                if (shouldDropPacket()) {
                    cout << "\033[31m+-------------------------------------------------------------+" << endl;
                    cout << "|[WARNING] ACK丢包测试 - 丢失: " << seqNum << "号 数据包的确认回复 " << endl;
                    cout << "+-------------------------------------------------------------+\033[0m" << endl;
                }
                else {
                    sendto(socketServer, receiveBuffer, sizeof(ackPacket), 0, (sockaddr*)&clieAddr, clieAddrlen);
                    cout << "\033[33m[SEND]\033[0m 发送确认信息 - 确认号: " << int(ackPacket.ack) << ", 校验和: " << int(packet.checksum) << endl;
                }
            }

            // 如果序列号在当前接收窗口内
            if ((seqNum >= rcv_base) && (seqNum < rcv_base + WindowSizeSize)) {
                // 如果以前没有收到过该序列号的数据包，则缓存起来
                if (!isReceived[bufferIndex]) {
                    // 复制数据到缓冲区
                    memcpy(packetBuffer[bufferIndex], receiveBuffer + sizeof(packet), packet.datasize);
                    isReceived[bufferIndex] = true;
                    cout << "\033[36m[INFO]\033[0m 数据包成功接收并缓存 - 序列号: " << seqNum << endl;

                    // 如果是窗口左边界，尝试交付数据
                    if (seqNum == rcv_base) {
                        while (isReceived[rcv_base % (2 * WindowSizeSize)]) {
                            memcpy(Message + totalDataLength, packetBuffer[rcv_base % (2 * WindowSizeSize)], packet.datasize);
                            totalDataLength += packet.datasize;
                            isReceived[rcv_base % (2 * WindowSizeSize)] = false;
                            rcv_base++;
                            cout << "\033[35m[MOVING]\033[0m 收到顺序到来的确认号 - 窗口滑动 - 从 " << rcv_base << " 到 " << rcv_base + WindowSizeSize << endl;
                        }
                    }
                }
                else {
                    cout << "\033[31m[WARNING]\033[0m 重复数据包 - 序列号: " << seqNum << endl;
                    // 即使是重复的数据包也发送ACK
                    sendto(socketServer, receiveBuffer, sizeof(ackPacket), 0, (sockaddr*)&clieAddr, clieAddrlen);
                    cout << "\033[33m[SEND]\033[0m 重复数据包的确认信息已发送 - 确认号: " << int(ackPacket.ack) << endl;
                }
            }
        }
    }
    // 发送结束标志
    packet.tag = OVER;
    packet.checksum = 0;
    packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
    memcpy(receiveBuffer, &packet, sizeof(packet));
    sendto(socketServer, receiveBuffer, sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen);
    cout << "\033[33m[SEND]\033[0m 结束标志已发送！" << endl;

    // 清理资源
    delete[] receiveBuffer;
    for (int i = 0; i < 2 * WindowSizeSize; ++i) {
        delete[] packetBuffer[i];
    }
    delete[] packetBuffer;
    delete[] isReceived;

    return totalDataLength;
}


int main()
{
    cout << "\033[33m" << "======================= 程序开始 =======================" << "\033[0m" << endl;

    // 初始化Winsock
    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;
    if (WSAStartup(wVersionRequested, &wsaData) != 0)
    {
        cout << "\033[31m" << "Winsock 初始化失败！" << "\033[0m" << endl;
        return 1;
    }

    // 创建UDP套接字
    SOCKET server = socket(AF_INET, SOCK_DGRAM, 0);
    if (server == SOCKET_ERROR)
    {
        cout << "\033[31m" << "套接字创建失败，错误码：" << WSAGetLastError() << "\033[0m" << endl;
        WSACleanup();
        return 0;
    }

    cout << "\033[32m" << "服务器套接字创建成功" << "\033[0m" << endl;

    // 设置服务器地址
    SOCKADDR_IN addr;
    memset(&addr, 0, sizeof(sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, IP, &addr.sin_addr.s_addr);

    // 绑定套接字
    if (bind(server, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        cout << "\033[31m" << "绑定失败，错误码：" << WSAGetLastError() << "\033[0m" << endl;
        closesocket(server);
        WSACleanup();
        return 0;
    }

    // 等待客户端连接
    int length = sizeof(addr);
    cout << "\033[33m" << "等待客户端连接请求...\n" << "\033[0m";
    int label = Client_Server_Connect(server, addr, length);

    cout << "\033[33m" << "数据缓冲区大小：" << DEFAULT_BUFFER_SIZE << " 滑动窗口缓冲区大小：" << DEFAULT_WindowSize_SIZE << "\033[33m" << endl;

    if (label == 0) { // 接收数据
        while (true) {
            cout << "\033[33m" << "======================= 等待接收数据 =======================" << "\033[0m" << endl;

            unique_ptr<char[]> F_name(new char[20]);
            unique_ptr<char[]> Message(new char[100000000]);
            int name_len = RecvMessage(server, addr, length, F_name.get(), DEFAULT_BUFFER_SIZE, DEFAULT_WindowSize_SIZE);

            if (name_len == 999) { // 检查是否是全局结束标志
                cout << "\033[32m" << "接收到全局结束标志，退出接收循环" << "\033[0m" << endl;
                break;
            }

            int file_len = RecvMessage(server, addr, length, Message.get(), DEFAULT_BUFFER_SIZE, DEFAULT_WindowSize_SIZE); // 接收文件内容
            string filename(F_name.get(), name_len); // 构造文件名字符串
            cout << "\033[32m" << "接收到的文件名：" << filename << "\033[0m" << endl;
            cout << "\033[32m" << "接收到的文件大小：" << file_len << "\033[0m" << " 字节" << endl;

            ofstream file_stream(filename, ios::binary); // 创建文件流
            if (!file_stream) { // 检查文件是否打开成功
                cout << "\033[31m" << "文件打开失败" << "\033[0m" << endl;
                continue; // 打开失败，继续下一轮循环
            }

            file_stream.write(Message.get(), file_len);// 写入文件内容
            file_stream.close();

            cout << "\033[32m" << "======================= 数据接收完毕，文件已保存 =======================" << "\033[0m" << endl;
        }
    }
    else if (label == 1) { // 发送数据
        while (true) {
            cout << "\033[33m" << "======================= 选择要发送的文件 =======================" << "\033[0m" << endl;
            char InFileName[20];
            cout << "\033[33m" << "输入文件名（输入 'q' 退出）:" << "\033[0m" << endl;
            cin >> InFileName;

            if (strcmp(InFileName, "q") == 0) { // 检查是否输入退出指令
                Packet_Header packet;
                unique_ptr<char[]> buffer(new char[sizeof(packet)]); // 创建缓冲区
                packet.tag = END; // 设置结束标志
                packet.checksum = compute_sum((WORD*)&packet, sizeof(packet)); // 计算校验和
                memcpy(buffer.get(), &packet, sizeof(packet)); // 复制到缓冲区
                sendto(server, buffer.get(), sizeof(packet), 0, (sockaddr*)&addr, length); // 发送结束标志
                cout << "\033[32m" << "发送全局结束标志至客户端" << "\033[0m" << endl;
                break; // 退出循环
            }

            ifstream file_stream(InFileName, ios::binary | ios::ate); // 打开文件
            if (!file_stream) { // 检查文件是否打开成功
                cout << "\033[31m" << "文件打开失败" << "\033[0m" << endl;
                continue;
            }

            int F_length = static_cast<int>(file_stream.tellg()); // 获取文件大小
            file_stream.seekg(0, ios::beg); // 重置文件指针
            unique_ptr<char[]> FileBuffer(new char[F_length]); // 创建文件内容缓冲区
            file_stream.read(FileBuffer.get(), F_length); // 读取文件内容

            cout << "\033[32m" << "发送文件数据大小：" << F_length << " 字节" << "\033[0m" << endl;

            SendMessage(server, addr, length, InFileName, strlen(InFileName), DEFAULT_BUFFER_SIZE, DEFAULT_WindowSize_SIZE); // 发送文件名
            clock_t start = clock(); // 记录开始时间
            SendMessage(server, addr, length, FileBuffer.get(), F_length, DEFAULT_BUFFER_SIZE, DEFAULT_WindowSize_SIZE); // 发送文件内容
            clock_t end = clock(); // 记录结束时间
            cout << "\033[33m" << "传输总用时：" << static_cast<double>(end - start) << "\033[0m" << endl;
            cout << "\033[33m" << "吞吐率：" << static_cast<double>(F_length) / ((end - start)) << "\033[0m" << endl;
            cout << "\033[33m" << "=====================================================================" << "\033[0m" << endl;
        }
    }

    // 断开连接并清理资源
    Client_Server_Disconnect(server, addr, length); // 断开连接
    closesocket(server);
    WSACleanup();
    cout << "\033[33m" << "======================= 程序结束 =======================" << "\033[0m" << endl;
    system("pause");
    return 0;
}