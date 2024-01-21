#include <sys/types.h>
#include <string.h>
#include <string>
#include <WinSock2.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <fstream>
#include <random>
#include <thread>
#include <chrono>
#include <ctime>
#pragma comment(lib, "ws2_32.lib")

using namespace std;

USHORT PORT = 8888;
#define IP "127.0.0.1"
#define DEFAULT_BUFFER_SIZE  4096
#define DEFAULT_WINDOW_SIZE  4
#define RESEND_TNTERVAL  1
#define PACKET_DELAY_MS  1 
#define MAX_RETRY_COUNT 8
#define LOSS_RATE  0.1 

const BYTE SYN = 0x1;		//开始新连接请求：SYN = 1 ACK = 0 FIN = 0
const BYTE ACK = 0x2;		//确认收到信息：SYN = 0 ACK = 1 FIN = 0
const BYTE ACK_SYN = 0x3;	//确认连接请求：SYN = 1 ACK = 1 FIN = 0
const BYTE FIN = 0x4;		//开始终止连接：FIN = 1 ACK = 0 SYN = 0
const BYTE FIN_ACK = 0x6;	//确认连接终止：FIN = 1 ACK = 1 SYN = 0
const BYTE OVER = 0x8;		//数据传输结束
const BYTE END = 0x16;		//通信过程全局结束

// 随机数生成器的初始化
random_device rd;
mt19937 gen(rd());
uniform_int_distribution<> dis(0, 99);

bool shouldDropPacket() {
    return dis(gen) < (LOSS_RATE * 100);
}

typedef struct Packet_Header
{
    WORD datasize;		// 数据长度
    BYTE tag;			// 标签，八位，使用后四位，排列是OVER FIN ACK SYN 
    BYTE WindowSize;	// 窗口大小
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

// 延迟函数
void delayPacket() {
    this_thread::sleep_for(chrono::milliseconds(PACKET_DELAY_MS));//使当前线程休眠（暂停执行）一段时间
}

// 计算校验和
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
// 参数：socketClient - 客户端套接字，servAddr - 服务器地址，servAddrlen - 服务器地址长度，label - 标签
int Client_Server_Connect(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, int label) {
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet)]);  // 智能指针：用于存储发送和接收的分组

    try {
        // 第一次握手：客户端首先向服务端发送SYN，建立连接请求
        packet.tag = SYN;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));

        if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
            throw runtime_error("发送SYN失败，错误码：" + to_string(WSAGetLastError()));
        }
        cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
        cout << "\033[32m" << "| 成功发送第一次握手信息 |" << "\033[0m" << endl;

        // Jacobson/Karels算法初始化RTT相关参数
        double estimatedRTT = 1.0;  // 估计的RTT，初始值设为1秒
        double devRTT = 0.0;        // RTT偏差
        const double alpha = 0.125; // 估计RTT的权重
        const double beta = 0.25;   // 偏差权重
        double timeoutDuration = estimatedRTT + 4 * devRTT;  // 初始化超时时间

        u_long mode = 1; // 设置为非阻塞模式
        ioctlsocket(socketClient, FIONBIO, &mode);

        // 第二次握手：客户端接收服务端回传的握手（SYN-ACK）
        clock_t start = clock();
        while (recvfrom(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
            if (double(clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
                start = clock();
                cout << "\033[34m" << "第一次握手超时，正在进行重传" << "\033[0m" << endl;
                timeoutDuration = estimatedRTT + 4 * devRTT;
            }
        }

        double sampleRTT = double(clock() - start) / CLOCKS_PER_SEC;
        estimatedRTT = (1 - alpha) * estimatedRTT + alpha * sampleRTT;
        devRTT = (1 - beta) * devRTT + beta * abs(sampleRTT - estimatedRTT);
        timeoutDuration = estimatedRTT + 4 * devRTT;

        mode = 0; // 恢复阻塞模式
        ioctlsocket(socketClient, FIONBIO, &mode);

        memcpy(&packet, buffer.get(), sizeof(packet));
        if (!(packet.tag == ACK && compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            throw runtime_error("无法接收服务端回传ACK，或校验和错误");
        }
        cout << "\033[32m" << "| 成功接收第二次握手信息 |" << "\033[0m" << endl;

        // 第三次握手：客户端发送ACK包，完成三次握手
        packet.tag = ACK_SYN;
        packet.datasize = label;
        packet.checksum = 0;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
            throw runtime_error("发送ACK_SYN失败，错误码：" + to_string(WSAGetLastError()));
        }

        cout << "\033[32m" << "| 成功发送第三次握手信息 |" << "\033[0m" << endl;
        cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
        cout << "\033[32m" << "客户端与服务端成功进行三次握手建立连接！可以开始发送/接收数据" << "\033[0m" << endl;
    }
    catch (const runtime_error& e) {
        cout << "\033[31m" << "异常发生: " << e.what() << "\033[0m" << endl;
        return -1;
    }
    return 1;
}

// 客户端与服务器端断开连接（四次挥手)
// 参数：socketClient - 客户端套接字，servAddr - 服务器地址，servAddrlen - 服务器地址长度
int Client_Server_Disconnect(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen) {
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet)]);

    try {
        // 客户端第一次发起挥手（FIN_ACK）
        packet.tag = FIN_ACK;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
            throw runtime_error("发送FIN_ACK失败，错误码：" + to_string(WSAGetLastError()));
        }
        cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
        cout << "\033[32m" << "| 成功发送第一次挥手信息 |" << "\033[0m" << endl;

        // 等待接收服务端发来的第二次挥手
        clock_t start = clock(); // 开始计时
        int retryCount = 0;
        int timeoutDuration = 1; // 初始超时时间为1秒

        while (true) {
            if (recvfrom(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
                if ((clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                    retryCount++;
                    if (retryCount > MAX_RETRY_COUNT) {
                        throw runtime_error("第二次挥手重传次数超过限制，错误码：" + to_string(WSAGetLastError()));
                    }
                    cout << "\033[34m" << "第二次挥手超时，正在进行第 " << retryCount << " 次重传" << "\033[0m" << endl;
                    if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
                        throw runtime_error("重传失败，错误码：" + to_string(WSAGetLastError()));
                    }
                    start = clock(); // 重置计时器
                    timeoutDuration *= 2; // 指数退避
                }
            }
            else {
                cout << "\033[32m" << "| 成功接收第二次挥手信息 |" << "\033[0m" << endl;
                break;
            }
        }

        // 等待服务器的第三次挥手(FIN_ACK)
        start = clock(); // 重置计时器
        retryCount = 0;
        timeoutDuration = 1; // 重置超时时间
        while (true) {
            if (recvfrom(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
                if ((clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                    retryCount++;
                    if (retryCount > MAX_RETRY_COUNT) {
                        throw runtime_error("第三次挥手重传次数超过限制，错误码：" + to_string(WSAGetLastError()));
                    }
                    cout << "\033[34m" << "等待第三次挥手超时，正在进行第 " << retryCount << " 次重传" << "\033[0m" << endl;
                    start = clock(); // 重置计时器
                    timeoutDuration *= 2; // 指数退避
                }
            }
            else {
                cout << "\033[32m" << "| 成功接收第三次挥手信息 |" << "\033[0m" << endl;
                break;
            }
        }

        // 客户端发送第四次挥手数据(ACK)
        packet.tag = ACK;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));

        if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
            throw runtime_error("发送第四次挥手数据失败，错误码：" + to_string(WSAGetLastError()));
        }

        cout << "\033[32m" << "| 成功发送第四次挥手信息 |" << "\033[0m" << endl;
        cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
        cout << "\033[32m" << "客户端与服务端成功断开连接！" << "\033[0m" << endl;
    }
    catch (const runtime_error& e) {
        cout << "\033[31m" << "断开连接过程中发生异常: " << e.what() << "\033[0m" << endl;
        return -1;
    }

    return 1;
}

// SR发送端函数
void SendMessage(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, char* Message, int mes_size, int MAX_SIZE, int WindowSize) {
    Packet_Header packet;
    int totalPacketNum = mes_size / MAX_SIZE + (mes_size % MAX_SIZE != 0);
    int base = 0;           // 窗口基序号
    int nextSeqNum = 0;     // 分组序列号

    // 初始化发送缓冲区
    char** stagingBuffer = new(nothrow) char* [WindowSize];
    int* stagingBufferLengths = new(nothrow) int[WindowSize];
    for (int i = 0; i < WindowSize; i++) {
        stagingBuffer[i] = new(nothrow) char[sizeof(packet) + MAX_SIZE];
    }

    // 初始化分组确认状态和定时器
    bool* ackReceived = new(nothrow) bool[WindowSize];
    clock_t* packetTimers = new(nothrow) clock_t[WindowSize];
    bool* timerRunning = new(nothrow) bool[WindowSize];
    for (int i = 0; i < WindowSize; i++) {
        ackReceived[i] = false;
        timerRunning[i] = false;
    }

    // 设置为非阻塞模式
    u_long socketMode = 1;
    ioctlsocket(socketClient, FIONBIO, &socketMode);

    // 发送分组
    while (base <  totalPacketNum) {
        // 发送窗口内的分组
        while (nextSeqNum < base + WindowSize && nextSeqNum < totalPacketNum) {
            // 计算分组大小
            int packetDataSize = (nextSeqNum == totalPacketNum - 1) ? mes_size - (totalPacketNum - 1) * MAX_SIZE : MAX_SIZE;
            
            // 设置分组头部信息
            packet.tag = 0;
            packet.seq = nextSeqNum % 256;
            packet.seq_quotient = nextSeqNum / 256;                 // 用于接收端恢复实际的序列号
            packet.datasize = packetDataSize;
            packet.WindowSize = WindowSize - (nextSeqNum - base);   // 当前窗口中还可以发送的分组数量
            packet.checksum = 0;
            packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));

            // 复制分组到发送缓冲区
            memcpy(stagingBuffer[nextSeqNum % WindowSize], &packet, sizeof(packet));
            char* messageFragment = Message + nextSeqNum * MAX_SIZE;
            memcpy(stagingBuffer[nextSeqNum % WindowSize] + sizeof(packet), messageFragment, packetDataSize);
            stagingBufferLengths[nextSeqNum % WindowSize] = packetDataSize;


            // 判断是否应该丢包
            if (shouldDropPacket()) {
                cout << "\033[31m+-------------------------------------------------------------+" << endl;
                cout << "|[WARNING] 分组丢包测试 - 丢失: " << nextSeqNum << "号 数据包 " << endl;
                cout << "+-------------------------------------------------------------+\033[0m" << endl;
            }
            else {
                sendto(socketClient, stagingBuffer[nextSeqNum % WindowSize], sizeof(packet) + packetDataSize, 0, (sockaddr*)&servAddr, servAddrlen);
                cout << "\033[33m[SEND]\033[0m 发送分组 - 序列号: " << nextSeqNum << "，packet序列号: " << int(packet.seq) << ", 校验和: " << int(packet.checksum) << "" << endl;
            }
            
            
            // 启动或重置定时器,并且针对每个发送的分组独立地跟踪其超时状态
            packetTimers[nextSeqNum % WindowSize] = clock();
            timerRunning[nextSeqNum % WindowSize] = true;

            nextSeqNum++;
        }

        char receiveBuffer[sizeof(packet)];

        // 重传分组
        while (recvfrom(socketClient, receiveBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
            // 遍历所有已发送但尚未收到ACK确认的分组
            for (int i = base; i < nextSeqNum; i++) {
                if (!ackReceived[i % WindowSize] && (clock() - packetTimers[i % WindowSize]) / CLOCKS_PER_SEC > RESEND_TNTERVAL) {
                    sendto(socketClient, stagingBuffer[i % WindowSize], sizeof(packet) + stagingBufferLengths[i % WindowSize], 0, (sockaddr*)&servAddr, servAddrlen);
                    cout << "\033[31m[WARNING]\033[0m 没有接收到ack，触发超时 - 重传分组，未确认包编号：" << i << endl;
                    packetTimers[i % WindowSize] = clock();  
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
        int packetIndex = int(packet.ack) % WindowSize;

        // 检查是否重复接收
        if (!ackReceived[packetIndex]) {
            // 更新接收标记和定时器
            ackReceived[packetIndex] = true;
            timerRunning[packetIndex] = false;
            cout << "\033[32m[ACC]\033[0m 收到确认 - ACK: " << int(packet.ack) << "，对应窗口索引: " << packetIndex << endl;

            // 滑动窗口
            while (ackReceived[base % WindowSize] && base < nextSeqNum) {
                // 重置窗口滑动后新位置的ackReceived状态
                ackReceived[base % WindowSize] = false;
                timerRunning[base % WindowSize] = false;
                base++;
                cout << "\033[35m[MOVING]\033[0m 收到顺序到来的确认号 - 窗口滑动 - 从 " << base << " 到 " << base + WindowSize << endl;
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
    for (int i = 0; i < WindowSize; i++) {
        delete[] stagingBuffer[i];
    }
    delete[] stagingBuffer;
    delete[] stagingBufferLengths;

}

// SR接收端函数
int RecvMessage(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen, char* Message, int MAX_SIZE, int WindowSize) {
    Packet_Header packet;
    char* receiveBuffer = new (nothrow) char[sizeof(packet) + MAX_SIZE];
    int rcv_base = 0;               // 窗口基序号
    long totalDataLength = 0;       // 已接收的数据总长度

    // 初始化接收端缓冲区和标记数组
    char** packetBuffer = new char* [2 * WindowSize];  // 修改为2N大小的缓冲区
    bool* isReceived = new bool[2 * WindowSize];
    for (int i = 0; i < 2 * WindowSize; ++i) {
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
            int bufferIndex = seqNum % (2 * WindowSize);  // 索引适应2N大小的缓冲区
            Packet_Header ackPacket;

            // 检查序列号是否在2倍窗口范围内
            bool isInDoubleWindowSize = (seqNum >= rcv_base - WindowSize) && (seqNum < rcv_base + WindowSize);

            if (isInDoubleWindowSize) {
                // 发送ACK，即使数据包不在当前接收窗口内
                ackPacket.tag = 0;
                ackPacket.ack = seqNum;
                ackPacket.checksum = 0;
                ackPacket.checksum = compute_sum((WORD*)&ackPacket, sizeof(ackPacket));
                memcpy(receiveBuffer, &ackPacket, sizeof(ackPacket));
                sendto(socketServer, receiveBuffer, sizeof(ackPacket), 0, (sockaddr*)&clieAddr, clieAddrlen);
                cout << "\033[33m[SEND]\033[0m 发送确认信息 - 确认号: " << int(ackPacket.ack) << ", 校验和: " << int(packet.checksum) << endl;
            }

            // 如果序列号在当前接收窗口内
            if ((seqNum >= rcv_base) && (seqNum < rcv_base + WindowSize)) {
                // 如果以前没有收到过该序列号的数据包，则缓存起来
                if (!isReceived[bufferIndex]) {
                    // 复制数据到缓冲区
                    memcpy(packetBuffer[bufferIndex], receiveBuffer + sizeof(packet), packet.datasize);
                    isReceived[bufferIndex] = true;
                    cout << "\033[36m[INFO]\033[0m 数据包成功接收并缓存 - 序列号: " << seqNum << endl;

                    // 如果是窗口左边界，尝试交付数据
                    if (seqNum == rcv_base) {
                        while (isReceived[rcv_base % (2 * WindowSize)]) {
                            memcpy(Message + totalDataLength, packetBuffer[rcv_base % (2 * WindowSize)], packet.datasize);
                            totalDataLength += packet.datasize;
                            isReceived[rcv_base % (2 * WindowSize)] = false;
                            rcv_base++;
                            cout << "\033[35m[MOVING]\033[0m 收到顺序到来的确认号 - 窗口滑动 - 从 " << rcv_base << " 到 " << rcv_base + WindowSize << endl;
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
    for (int i = 0; i < 2 * WindowSize; ++i) {
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
    SOCKET client = socket(AF_INET, SOCK_DGRAM, 0);
    if (client == INVALID_SOCKET)
    {
        cout << "\033[31m" << "套接字创建失败，错误码：" << WSAGetLastError() << "\033[0m" << endl;
        WSACleanup();
        return 1;
    }

    cout << "\033[32m" << "客户端套接字创建成功" << "\033[0m" << endl;

    // 设置服务器地址
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(PORT);
    inet_pton(AF_INET, IP, &serveraddr.sin_addr.s_addr);

    // 选择操作模式
    cout << "\033[33m" << "请选择操作模式（发送0 / 接收1）：" << "\033[0m" << endl;
    int label;
    cin >> label;

    // 连接到服务器
    int length = sizeof(serveraddr);
    cout << "\033[33m" << "向服务器发起连接请求...\n" << "\033[0m";
    if (Client_Server_Connect(client, serveraddr, length, label) == -1)
    {
        cout << "\033[31m" << "连接建立失败。" << "\033[0m" << endl;
        closesocket(client);
        WSACleanup();
        return 1;
    }

    cout << "\033[33m" << "数据缓冲区大小：" << DEFAULT_BUFFER_SIZE << " 滑动窗口缓冲区大小：" << DEFAULT_WINDOW_SIZE << "\033[33m" << endl;

    if (label == 0) // 发送数据
    {
        while (true)
        {
            cout << "\033[33m" << "======================= 选择要发送的文件 =======================" << "\033[0m" << endl;
            char InFileName[20];
            cout << "\033[33m" << "输入文件名（输入 'q' 退出）:" << "\033[0m" << endl;
            cin >> InFileName;

            if (strcmp(InFileName, "q") == 0)
            {
                Packet_Header packet;
                unique_ptr<char[]> buffer(new char[sizeof(packet)]);
                packet.tag = END;
                packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
                memcpy(buffer.get(), &packet, sizeof(packet));
                sendto(client, buffer.get(), sizeof(packet), 0, (sockaddr*)&serveraddr, length);
                cout << "\033[32m" << "发送全局结束标志至服务器" << "\033[0m" << endl;
                break;
            }

            ifstream file_stream(InFileName, ios::binary | ios::ate);
            if (!file_stream)
            {
                cout << "\033[31m" << "文件打开失败" << "\033[0m" << endl;
                continue;
            }

            int F_length = static_cast<int>(file_stream.tellg());
            file_stream.seekg(0, file_stream.beg);
            unique_ptr<char[]> FileBuffer(new char[F_length]);
            file_stream.read(FileBuffer.get(), F_length);

            cout << "\033[32m" << "发送文件数据大小：" << F_length << " 字节" << "\033[0m" << endl;

            SendMessage(client, serveraddr, length, InFileName, strlen(InFileName), DEFAULT_BUFFER_SIZE, DEFAULT_WINDOW_SIZE);
            clock_t start = clock();
            SendMessage(client, serveraddr, length, FileBuffer.get(), F_length, DEFAULT_BUFFER_SIZE, DEFAULT_WINDOW_SIZE);
            clock_t end = clock();
            cout << "\033[32m" << "传输总时长：" << (end - start) / CLOCKS_PER_SEC << " 秒。" << "\033[0m" << endl;
            cout << "\033[32m" << "吞吐率：" << static_cast<float>(F_length) / ((end - start) / CLOCKS_PER_SEC) << " 字节/秒。" << "\033[0m" << endl;
            cout << "\033[33m" << "=====================================================================" << "\033[0m" << endl;
        }
    }
    else if (label == 1)
    {
        while (true)
        {
            cout << "\033[33m" << "======================= 等待接收数据 =======================" << "\033[0m" << endl;

            unique_ptr<char[]> F_name(new char[20]);
            unique_ptr<char[]> Message(new char[100000000]);
            int name_len = RecvMessage(client, serveraddr, length, F_name.get(), DEFAULT_BUFFER_SIZE, DEFAULT_WINDOW_SIZE);

            if (name_len == 999)
            {
                cout << "\033[32m" << "接收到全局结束标志，退出接收循环" << "\033[0m" << endl;
                break;
            }

            int file_len = RecvMessage(client, serveraddr, length, Message.get(), DEFAULT_BUFFER_SIZE, DEFAULT_WINDOW_SIZE);
            string fileName(F_name.get(), name_len);
            cout << "\033[32m" << "接收的文件名：" << fileName << "\033[0m" << endl;
            cout << "\033[32m" << "接收的文件数据大小：" << file_len << " 字节" << "\033[0m" << endl;

            ofstream file_stream(fileName, ofstream::binary);
            if (!file_stream) {
                cout << "\033[31m" << "文件打开失败！" << "\033[0m" << endl;
                continue;
            }
            file_stream.write(Message.get(), file_len);
            file_stream.close();

            cout << "\033[32m" << "======================= 数据接收完毕，文件已保存 =======================" << "\033[0m" << endl;
        }
    }

    Client_Server_Disconnect(client, serveraddr, length);
    this_thread::sleep_for(chrono::milliseconds(500));
    closesocket(client);
    WSACleanup();
    cout << "\033[33m" << "======================= 程序结束 =======================" << "\033[0m" << endl;
    system("pause");
    return 0;
}
