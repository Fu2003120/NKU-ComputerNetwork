#include <sys/types.h>
#include <string.h>
#include <string>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <fstream>
#include <string.h>
#include <random>
#include <chrono>
#include <thread>
#pragma comment(lib, "ws2_32.lib")
using namespace std;

USHORT PORT = 8888;
#define IP "127.0.0.1"
#define DEFAULT_BUFFER_SIZE  1024
#define DEFAULT_WINDOW_SIZE  8
const int MAX_RETRY_COUNT = 10;  // 最大重传次数
const BYTE SYN = 0x1;		//开始新连接请求：SYN = 1 ACK = 0 FIN = 0
const BYTE ACK = 0x2;		//确认收到信息：SYN = 0 ACK = 1 FIN = 0
const BYTE ACK_SYN = 0x3;	//确认连接请求：SYN = 1 ACK = 1 FIN = 0
const BYTE FIN = 0x4;		//开始终止连接：FIN = 1 ACK = 0 SYN = 0
const BYTE FIN_ACK = 0x6;	//确认连接终止：FIN = 1 ACK = 1 SYN = 0
const BYTE OVER = 0x8;		//数据传输结束
const BYTE END = 0x16;		//通信过程全局结束
int PACKET_DELAY_MS = 1; // 毫秒延时

typedef struct Packet_Header
{
    WORD datasize;		// 数据长度
    BYTE tag;			// 标签，八位，使用后四位，排列是OVER FIN ACK SYN 
    BYTE window;		// 窗口大小（未使用）
    BYTE seq;			// 序列号
    BYTE ack;			// 确认号
    WORD checksum;		// 校验和

    // 初始化
    Packet_Header()
    {
        datasize = 0;
        tag = 0;
        window = 0;
        seq = 0;
        ack = 0;
        checksum = 0;
    }
};

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

// 延迟函数
void delayPacket() {
    this_thread::sleep_for(chrono::milliseconds(PACKET_DELAY_MS));//使当前线程休眠（暂停执行）一段时间
}

// 客户端与服务端建立连接（采取三次握手的方式）
// 参数：socketClient - 客户端套接字，servAddr - 服务器地址，servAddrlen - 服务器地址长度，label - 标签
int Client_Server_Connect(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, int label) {
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet)]);  // 智能指针：用于存储发送和接收的数据包

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

// 接收数据
// 参数：socketServer - 服务器端的套接字，clieAddr - 客户端地址的结构，clieAddrlen - 客户端地址结构的长度
// Mes - 存储接收到的数据的缓冲区， MAX_SIZE - 每个数据包的最大大小
int RecvMessage(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen, char* Message, int MAX_SIZE, int Window) {
    Packet_Header packet;
    char* receiveBuffer = new char[sizeof(packet) + MAX_SIZE];  // 接收缓冲区
    int Ack_num = 1;  // 确认序列号
    int Seq_num = 0;  // 序列号
    long totalDataLength = 0;     // 接收到的数据总长度
    int singleDataLength = 0;     // 单次接收的数据长度
    bool timeoutTestFlag = true;  // 超时测试标志


    // 循环接收数据
    while (true)
    {
        while (recvfrom(socketServer, receiveBuffer, sizeof(packet) + MAX_SIZE, 0, (sockaddr*)&clieAddr, &clieAddrlen) <= 0);
        memcpy(&packet, receiveBuffer, sizeof(packet));

        // 随机超时重传测试
        if (((rand() % (255 - 1)) + 1) == 199 && timeoutTestFlag) {
            cout << endl << "\033[34m[TEST] \033[0m 随机超时重传测试触发 - Seq：" << int(packet.seq) << endl;
            timeoutTestFlag = false;
            continue;
        }

        // 收到全局结束标记
        if (packet.tag == END && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            cout << "\033[32m[INFO]\033[0m 全局结束标志已接收" << endl;
            return 999;
        }

        // 收到单次数据包发送结束标记
        if (packet.tag == OVER && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            cout << "\033[32m[INFO]\033[0m 结束标志已接收" << endl;
            break;
        }

        // 接收数据
        if (packet.tag == 0 && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            // 如果接收到的序列号不是预期的，发送重传请求
            if (packet.seq != Seq_num) {
                Packet_Header resendHeader;
                resendHeader.tag = 0;
                resendHeader.ack = Ack_num - 1;  // 累计确认：发送上一个确认的ACK
                resendHeader.checksum = 0;
                resendHeader.checksum = compute_sum((WORD*)&resendHeader, sizeof(resendHeader));
                memcpy(receiveBuffer, &resendHeader, sizeof(resendHeader));

                // delayPacket();

                sendto(socketServer, receiveBuffer, sizeof(resendHeader), 0, (sockaddr*)&clieAddr, clieAddrlen);
                cout << "\033[31m[ERROR]\033[0m 序列号错误 - 向客户端发送重传请求 - Ack" << int(packet.ack) << endl;
                continue;
            }

            // 成功接收数据
            singleDataLength = packet.datasize;
            cout << "\033[32m[INFO]\033[0m 接收数据包 - 数据大小: " << singleDataLength << " 字节, Tag: " << int(packet.tag) << ", Seq：" << int(packet.seq) << ", CheckSum: " << int(packet.checksum) << endl;
            memcpy(Message + totalDataLength, receiveBuffer + sizeof(packet), singleDataLength);
            totalDataLength += singleDataLength;

            // 确认接收成功，发送ACK
            packet.tag = 0;
            packet.ack = Ack_num++;
            packet.seq = Seq_num++;
            Seq_num = (Seq_num > 255 ? Seq_num - 256 : Seq_num);
            Ack_num = (Ack_num > 255 ? Ack_num - 256 : Ack_num);
            packet.datasize = 0;
            packet.checksum = 0;
            packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
            memcpy(receiveBuffer, &packet, sizeof(packet));

            if (((rand() % (255 - 1)) + 1) != 187) {
                sendto(socketServer, receiveBuffer, sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen);
                cout << "\033[32m[INFO]\033[0m 成功发送ACK响应 - Seq: " << int(packet.seq) << ", Ack: " << int(packet.ack) << endl;
            }
            else {
                cout << "\033[34m[TEST]\033[0m 累计确认测试触发 - 序列号: " << int(packet.seq) << ", 未发送ACK" << endl;
            }

            cout << "\033[32m[INFO]\033[0m 成功接收数据 - Seq: " << int(packet.seq) << ", 数据大小: " << singleDataLength << " 字节" << endl;
        }
        else if (packet.tag == 0) {  // 数据校验失败，请求重传
            Packet_Header resendHeader;
            resendHeader.tag = 0;
            resendHeader.ack = Ack_num - 1;  // 发送上一个确认的ACK
            resendHeader.checksum = 0;
            resendHeader.checksum = compute_sum((WORD*)&resendHeader, sizeof(resendHeader));
            memcpy(receiveBuffer, &resendHeader, sizeof(resendHeader));

            sendto(socketServer, receiveBuffer, sizeof(resendHeader), 0, (sockaddr*)&clieAddr, clieAddrlen);

            cout << "\033[31m[ERROR]\033[0m 数据校验失败 - 向发送端发送最后一个确认的ACK，Ack:" << int(packet.ack) << endl;
            continue;
        }
    }

    // 发送结束标志
    packet.tag = OVER;
    packet.checksum = 0;
    packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
    memcpy(receiveBuffer, &packet, sizeof(packet));
    sendto(socketServer, receiveBuffer, sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen);
    cout << "\033[32m[INFO]\033[0m 结束标志已发送" << endl;
    delete[] receiveBuffer;
    return totalDataLength;
}

// 发送数据
// socketClient - 客户端的套接字，servAddr - 服务器的地址信息，servAddrlen - 服务器地址信息的长度，
// Message - 要发送的消息的指针，mes_size - 消息的大小，MAX_SIZE - 每个数据包的最大大小，Window - 滑动窗口大小
void SendMessage(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, char* Message, int mes_size, int MAX_SIZE, int Window) {
    int totalPacketCount = mes_size / (MAX_SIZE)+(mes_size % MAX_SIZE != 0);    // 发送数据包总量
    int BaseIndex = -1;                                                         // 基序号索引 [0,totalPacketCount]
    int NextSeqNum = 0;                                                         // 下一个要发送数据包的索引 [0,totalPacketCount]
    int lastUnacknowledgedPacketIndex = 0;                                      // 最早发送尚未收到确认的数据包的索引 [0,totalPacketCount]
    int Seq_num = 0;                                                            // 序列号 [0,255]
    int Ack_num = 1;                                                            // 确认号 [0,255]

    Packet_Header packet;  

    // 创建数据暂存区
    char** stagingBuffer = new char* [Window];                                  // 发送缓冲区
    int* stagingBufferLengths = new int[Window];                                // 缓冲区中每个数据包长度
    for (int i = 0; i < Window; i++) {              
        stagingBuffer[i] = new char[sizeof(packet) + MAX_SIZE];                 // 初始化内存
    }

    // 设置为非阻塞模式
    u_long socketMode = 1;
    ioctlsocket(socketClient, FIONBIO, &socketMode);

    // 初始化定时器（GBN只需要设置一个定时器）
    clock_t timerStart = 0;
    bool timerRunning = false;

    clock_t startTime = clock(); // 用于计算时延吞吐率

    // 发送所有数据包
    while (BaseIndex < (totalPacketCount - 1)) {
        /*
        发送缓冲区中所有数据包：1.在发送缓冲区；2.没有超过总量

        BaseIndex   NextSeqNum    BaseIndex + Window         totalPacketCount
        +---------------+-----------------+---------- ... ... -----------+
        */
        while (NextSeqNum <= BaseIndex + Window && NextSeqNum < totalPacketCount)
        {
            cout << "\033[33m[INFO]\033[0m 准备发送数据包 - 当前滑动窗口 - BaseIndex: " << BaseIndex << ", NextSeqNum: " << NextSeqNum << endl;
            // 计算当前数据包大小：1.最后一个数据包：mes_size - (totalPacketCount - 1) * MAX_SIZE；2.其他数据包：MAX_SIZE
            int packetDataSize = (NextSeqNum == totalPacketCount - 1 ? mes_size - (totalPacketCount - 1) * MAX_SIZE : MAX_SIZE);
            // 设置数据包头部信息
            packet.tag = 0;
            packet.seq = Seq_num++;
            Seq_num = (Seq_num > 255 ? Seq_num - 256 : Seq_num);
            packet.datasize = packetDataSize;
            stagingBufferLengths[NextSeqNum % Window] = packetDataSize;         // GBN：缓冲区记录对应数据包长度
            packet.window = Window - (NextSeqNum - BaseIndex);                  // 剩余窗口大小
            packet.checksum = 0;
            packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));

            // 将数据包头部和数据先后复制到发送缓冲区（缓冲区能容纳Window个包）
            memcpy(stagingBuffer[NextSeqNum % Window], &packet, sizeof(packet));
            char* messageFragment = Message + NextSeqNum * MAX_SIZE;
            memcpy(stagingBuffer[NextSeqNum % Window] + sizeof(packet), messageFragment, packetDataSize);

            // 发送数据包

            // delayPacket();

            sendto(socketClient, stagingBuffer[NextSeqNum % Window], sizeof(packet) + packetDataSize, 0, (sockaddr*)&servAddr, servAddrlen);

            // 启动定时器
            if (!timerRunning) {
                timerStart = clock();
                timerRunning = true;
            }

            cout << "\033[32m[INFO]\033[0m 发送数据包 - 数据大小: " << packetDataSize << " 字节, Seq: " << int(packet.seq) << ", CheckSum: " << int(packet.checksum) << ", 首个未确认数据包编号: " << lastUnacknowledgedPacketIndex << endl;
            NextSeqNum++;
        }

        char* receiveBuffer = new char[sizeof(packet)];  // 接收缓冲区

        // 未收到接收端回复的确认信息
        while (recvfrom(socketClient, receiveBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {  
            if (timerRunning && (clock() - timerStart) / CLOCKS_PER_SEC > 2) {
                // GBN：重新发送最后一个被确认的数据包之后的所有数据包
                for (int temp = lastUnacknowledgedPacketIndex; temp < NextSeqNum; temp++) {
                    sendto(socketClient, stagingBuffer[temp % Window], sizeof(packet) + stagingBufferLengths[temp % Window], 0, (sockaddr*)&servAddr, servAddrlen);
                    cout << "\033[31m[WARNING]\033[0m 超时 - 重传数据包，未确认包编号：" << temp % Window << endl;
                }
                // 重置定时器
                timerStart = clock();
            }
        }

        // 收到接收端回复的确认信息
        memcpy(&packet, receiveBuffer, sizeof(packet));

        // 校验数据包
        if ((compute_sum((WORD*)&packet, sizeof(packet)) != 0)) {
            continue;
        }

        // 收到接收端的接收确认
        if (packet.ack == Ack_num) {
            // 更新确认号
            Ack_num = (Ack_num + 1) % 256;
            cout << "\033[32m[INFO]\033[0m 收到确认 - Ack: " << int(packet.ack) << endl;
            // GBN：滑动窗口
            BaseIndex++;
            lastUnacknowledgedPacketIndex++;
            // GBN：发送的所有数据包全部收到接收端的确认后，停止定时器
            if (lastUnacknowledgedPacketIndex == NextSeqNum) {
                timerRunning = false;
            }
            cout << "\033[33m[INFO]\033[0m 接收到ACK，更新滑动窗口 - BaseIndex: " << BaseIndex << ", NextSeqNum: " << NextSeqNum << endl;
        }
        else {
            // 保证出现序列号循环的情况下
            // -  dis > 0：接收ack是在当前ack之后 -> 正常情况
            // - dis <= 0：序列号出现循环：当前 ack 是 250，而收到的 ack 是 5，5 应该是在 250 之后的数 -> 计算方式变为: (int(packet.ack) + 256 - Ack_num)
            int dis = (int(packet.ack) - Ack_num) > 0 ? (int(packet.ack) - Ack_num) : (int(packet.ack) + 256 - Ack_num);
            
            int duplicateAckCount = 0;

            // 检测到重复确认
            if (packet.ack == (Ack_num == 0 ? 255 : Ack_num - 1)) {
                // 如果Ack_num是0，前一个确认号应该是255，否则就是Ack_num - 1。
                cout << "\033[31m[WARNING]\033[0m 收到重复确认，Ack: " << int(packet.ack) << endl;
                // 可以在这里实现快速重传机制（如果需要）
                /*
                duplicateAckCount++;
                if (duplicateAckCount >= 3) {
                    // 重传最早未被确认的数据包
                    int packetIndex = lastUnacknowledgedPacketIndex % Window;
                    sendto(socketClient, stagingBuffer[packetIndex], sizeof(packet) + stagingBufferLengths[packetIndex], 0, (sockaddr*)&servAddr, servAddrlen);
                    cout << "\033[31m[INFO]\033[0m 快速重传触发，重传数据包 Seq: " << lastUnacknowledgedPacketIndex << endl;

                    // 重置重复ACK计数
                    duplicateAckCount = 0;
                }
                */
            }
            // 发送的数据包接收方已经接受，但是接收方的确认信息丢失，表现为收到了期望Ack之后的Ack，发送方就可以假设所有之前的数据包都已经被接收方确认
            // 目的在于提高效率以及对接收端累计确认的信任
            else if (dis < Window || (Ack_num + dis) % 256 == packet.ack) {  //  (Ack_num + dis) % 256 == packet.ack 是为了处理循环的情况

                cout << endl << "\033[34m[INFO]\033[0m 累计确认处理触发" << endl;

                // 更新发送端的状态：移动窗口 + 更新期望的确认号
                while (Ack_num != (packet.ack + 1) % 256) {
                    cout << "\033[32m[INFO]\033[0m 累计确认 - Ack: " << Ack_num << endl;
                    BaseIndex++;
                    lastUnacknowledgedPacketIndex = (lastUnacknowledgedPacketIndex + 1) % Window;
                    Ack_num = (Ack_num + 1) % 256;
                    cout << "\033[33m[INFO]\033[0m 累计确认，更新滑动窗口 - BaseIndex: " << BaseIndex << ", NextSeqNum: " << NextSeqNum << endl;
                }
                cout << "\033[34m[INFO]\033[0m 累计确认处理结束\n" << endl;

            }
            else {
                // 异常情况：dis 大于窗口大小 或者 收到的ACK不是通过累计确认逻辑计算出的预期ACK
                // 重发所有未确认的数据包
                cout << "\033[31m[WARNING]\033[0m 检测到校验出错或ACK不合理，开始重传未确认数据包" << endl;
                for (int temp = BaseIndex + 1; temp <= BaseIndex + Window && temp < totalPacketCount; temp++) {
                    sendto(socketClient, stagingBuffer[temp % Window], sizeof(packet) + stagingBufferLengths[temp % Window], 0, (sockaddr*)&servAddr, servAddrlen);
                    cout << "\033[32m[INFO]\033[0m 重传数据包，Seq: " << temp % 256 << endl;
                }
                cout << "\033[32m[INFO]\033[0m 重传处理完成" << endl;
            }
        }

        // 清理接收缓冲区资源
        delete[] receiveBuffer;
    }

    // 结束时间和吞吐率计算
    clock_t endTime = clock();
    double totalDuration = double(endTime - startTime) / CLOCKS_PER_SEC;
    double throughput = mes_size / totalDuration;
    //cout << "\033[32m[INFO]\033[0m 总发送时间: " << totalDuration << " 秒, 吞吐率: " << throughput << " 字节/秒" << endl;

    // 发送结束标志
    packet.tag = OVER;
    char* endSignalBuffer = new char[sizeof(packet)];
    packet.checksum = 0;
    packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
    memcpy(endSignalBuffer, &packet, sizeof(packet));
    sendto(socketClient, endSignalBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
    cout << "\033[32m[INFO]\033[0m 结束标志已发送" << endl;

    // 确认结束标志的接收
    clock_t endSignalStartTime = clock();
    while (recvfrom(socketClient, endSignalBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
        if ((clock() - endSignalStartTime) / 1000 > 1) {
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
        cout << "\033[32m[INFO]\033[0m 成功接收到结束标志" << endl;
    }
    else {
        cout << "[ERROR] 无法接收客户端回传的结束标志" << endl;
    }
    return;



    // 清理结束信号缓冲区资源
    delete[] endSignalBuffer;

    // 清理发送缓冲区资源
    for (int i = 0; i < Window; i++) {
        delete[] stagingBuffer[i];
    }
    delete[] stagingBuffer;
    delete[] stagingBufferLengths;
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
