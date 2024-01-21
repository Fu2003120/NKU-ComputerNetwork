/*功能包括：建立连接、差错检测、确认重传等。流量控制采用停等机制*/

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
const int MAX_RETRY_COUNT = 10;  // 最大重传次数
const int TEST_TIME = 3;    //指数退避测试次数
const BYTE SYN = 0x1;		//开始新连接请求：SYN = 1 ACK = 0 FIN = 0
const BYTE ACK = 0x2;		//确认收到信息：SYN = 0 ACK = 1 FIN = 0
const BYTE ACK_SYN = 0x3;	//确认连接请求：SYN = 1 ACK = 1 FIN = 0
const BYTE FIN = 0x4;		//开始终止连接：FIN = 1 ACK = 0 SYN = 0
const BYTE FIN_ACK = 0x6;	//确认连接终止：FIN = 1 ACK = 1 SYN = 0
const BYTE OVER = 0x8;		//数据传输结束
const BYTE END = 0x16;		//通信过程全局结束
double PACKET_LOSS_RATE = 0.01; // 丢包率
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

// 丢包函数
bool shouldDropPacket() {
    random_device rd;
    mt19937 gen(rd());//初始化随机数生成器
    uniform_real_distribution<> dis(0, 1); //定义一个在 [0, 1] 范围内均匀分布的实数分布
    return dis(gen) < PACKET_LOSS_RATE;//并检查随机数是否小于设定的丢包率
}

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

// 客户端与服务端建立连接（三次握手）
// 参数：socketClient - 客户端套接字，servAddr - 服务器地址，servAddrlen - 服务器地址长度，label - 用于区分不同的客户端
int Client_Server_Connect(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, int label)
{
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet)]);  // 智能指针：用于存储发送和接收的数据包

    try {
        // 第一次：客户端首先向服务端发送SYN，建立连接请求
        packet.tag = SYN;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));// 将数据包复制到缓冲区

        // 模拟网络延迟
        delayPacket();

        // 发送SYN包到服务器
        if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
            throw runtime_error("发送SYN失败，错误码：" + to_string(WSAGetLastError()));
        }
        cout << "成功发送第一次握手信息" << endl;

        // Jacobson/Karels算法
        // 初始化RTT相关参数
        double estimatedRTT = 1.0;  // 估计的RTT，初始值设为1秒
        double devRTT = 0.0;        // RTT偏差
        const double alpha = 0.125; // 估计RTT的权重
        const double beta = 0.25;   // 偏差权重
        double timeoutDuration = estimatedRTT + 4 * devRTT;  // 初始化超时时间
        cout << "初始的超时时间: " << timeoutDuration << " 秒" << endl;

        // 设置为非阻塞模式：如果没有收到信息，程序将停留在读取函数调用处，直到数据到达并被读取。
        u_long mode = 1;
        ioctlsocket(socketClient, FIONBIO, &mode);

        // 第二次：客户端接收服务端回传的握手（SYN-ACK）
        clock_t start = clock();// 开始计时
        while (recvfrom(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
            // 如果等待超过超时时间，则重新发送SYN包并重置计时器
            if (double(clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
                start = clock();
                cout << "第一次握手超时，正在进行重传" << endl;
                timeoutDuration = estimatedRTT + 4 * devRTT;  // 更新超时时间
            }
        }

        // 更新RTT估计
        double sampleRTT = double(clock() - start) / CLOCKS_PER_SEC;
        estimatedRTT = (1 - alpha) * estimatedRTT + alpha * sampleRTT;
        devRTT = (1 - beta) * devRTT + beta * abs(sampleRTT - estimatedRTT);
        timeoutDuration = estimatedRTT + 4 * devRTT;  // 更新超时时间

        cout << "样本RTT: " << sampleRTT << " 秒" << endl;
        cout << "估计RTT: " << estimatedRTT << " 秒" << endl;
        cout << "RTT偏差: " << devRTT << " 秒" << endl;
        cout << "更新后的超时时间: " << timeoutDuration << " 秒" << endl;

        // 恢复阻塞模式
        mode = 0;
        ioctlsocket(socketClient, FIONBIO, &mode);

        // 检查接收到的SYN-ACK包是否正确
        memcpy(&packet, buffer.get(), sizeof(packet));
        if (!(packet.tag == ACK && compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            throw runtime_error("无法接收服务端回传ACK，或校验和错误");
        }
        cout << "成功收到第二次握手信息" << endl;

        // 第三步：客户端发送ACK包，完成三次握手
        packet.tag = ACK_SYN;
        packet.datasize = label;
        packet.checksum = 0;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
            throw runtime_error("发送ACK_SYN失败，错误码：" + to_string(WSAGetLastError()));
        }

        cout << "成功发送第三次握手信息" << endl;
        cout << "客户端与服务端成功进行三次握手建立连接！可以开始发送/接收数据" << endl;
    }
    catch (const runtime_error& e) {
        cout << "异常发生: " << e.what() << endl;
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
        cout << "客户端发送第一次挥手信息(FIN_ACK)成功" << endl;

        // 等待接收服务端发来的第二次挥手
        clock_t start = clock(); // 开始计时
        int retryCount = 0;
        int timeoutDuration = 1; // 初始超时时间为1秒

        // 设置阻塞模式与while(true)循环均可以实现超时重传
        while (true) {
            // 接收失败
            if (recvfrom(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
                // 超时重传
                if ((clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                    retryCount++;
                    if (retryCount > MAX_RETRY_COUNT) { // 若超出最大重传次数，报错
                        throw runtime_error("第二次挥手重传次数超过限制，错误码：" + to_string(WSAGetLastError()));
                    }
                    if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
                        throw runtime_error("重传失败，错误码：" + to_string(WSAGetLastError()));
                    }                    
                    cout << "第二次挥手超时，正在进行第 " << retryCount << " 次重传" << endl;
                    start = clock(); // 重置计时器
                    timeoutDuration *= 2; // 指数退避，超时时间加倍
                }
                // else:程序正在等待响应，且还未达到超时时间
            }
            else {
                cout << "客户端成功接收第二次挥手信息(ACK)" << endl;
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
                    if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
                        throw runtime_error("重传失败，错误码：" + to_string(WSAGetLastError()));
                    }
                    cout << "等待第三次挥手超时，正在进行第 " << retryCount << " 次重传" << endl;
                    start = clock(); // 重置计时器
                    timeoutDuration *= 2; // 指数退避
                }
            }
            else {
                cout << "客户端成功接收第三次挥手信息(FIN_ACK)" << endl;
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

        cout << "客户端发送第四次挥手信息(ACK)成功" << endl;
        cout << "客户端与服务端成功断开连接！" << endl;
    }
    catch (const runtime_error& e) {
        cout << "断开连接过程中发生异常: " << e.what() << endl;
        return -1;
    }

    return 1; 
}

// 发送数据
// socketClient - 客户端的套接字，servAddr - 服务器的地址信息，servAddrlen - 服务器地址信息的长度，
// Message - 要发送的消息的指针，mes_size - 消息的大小，MAX_SIZE - 每个数据包的最大大小
void SendMessage(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, char* Message, int mes_size, int MAX_SIZE)
{
    int packet_num = mes_size / (MAX_SIZE)+(mes_size % MAX_SIZE != 0);// 计算需要的数据包数量
    int Seq_num = 0;  //初始化序列号
    int TestFlag = 0; //指数退避算法的堵塞次数
    Packet_Header packet;
    u_long mode = 1;
    ioctlsocket(socketClient, FIONBIO, &mode);  // 非阻塞模式

    try
    {
        // 循环发送所有数据包
        for (int i = 0; i < packet_num; i++)
        {
            // 计算当前包的数据长度
            int data_len = (i == packet_num - 1 ? mes_size - (packet_num - 1) * MAX_SIZE : MAX_SIZE);
            // 发送缓冲区
            char* buffer = new char[sizeof(packet) + data_len]; 
            packet.tag = 0;
            packet.seq = Seq_num;
            packet.datasize = data_len;
            packet.checksum = 0;
            packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
            // 将数据包头部复制到缓冲区
            memcpy(buffer, &packet, sizeof(packet));
            // 计算当前数据包的起始位置
            char* mes = Message + i * MAX_SIZE;
            // 将数据复制到缓冲区
            memcpy(buffer + sizeof(packet), mes, data_len);

            // 模拟延时
            delayPacket();

            // 模拟丢包
            bool packetDropped = shouldDropPacket();
            if (packetDropped) {
                cout << "模拟丢弃一个数据包" << endl;
                // 在这里不发送数据，但仍然进入接收确认的逻辑
            }
            else {
                // 发送数据
                sendto(socketClient, buffer, sizeof(packet) + data_len, 0, (sockaddr*)&servAddr, servAddrlen);
                cout << "开始发送消息...... 数据大小：" << data_len << " 字节！" << " Tag：" << int(packet.tag) << " Seq：" << int(packet.seq) << " CheckSum：" << int(packet.checksum) << endl;
            }

            int retryCount = 0;       // 重传计数器
            int timeoutDuration = 1;  // 初始超时时间为1秒
            clock_t start = clock();  // 记录初始发送时间
            clock_t lastSendTime = start;  // 记录上一次发送时间

            // 等待接收确认响应
            while (recvfrom(socketClient, buffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
                // 超时重传逻辑：如果超过了超时时间，需要重传
                clock_t currentTime = clock();
                if ((currentTime - start) / CLOCKS_PER_SEC > timeoutDuration) {
                    if (retryCount >= MAX_RETRY_COUNT) {
                        throw runtime_error("重传次数超过限制，错误码：" + to_string(WSAGetLastError()));
                    }

                    // 计算自上次发送以来经过的时间
                    double timeSinceLastSend = double(currentTime - lastSendTime) / CLOCKS_PER_SEC;
                    cout << "第 " << retryCount + 1 << " 次重传，距上次发送经过 " << timeSinceLastSend << " 秒" << endl;

                    // 重传数据包
                    if (TestFlag < TEST_TIME) //此时先不发送数据包，测试指数退避算法
                    {
                        if (TestFlag == 0) {
                            cout << endl << "======测试指数退避算法======" << endl;
                        }
                        TestFlag++;
                        cout << "TestFlag:" << TestFlag << endl;
                        // 指数退避
                        lastSendTime = clock();  // 更新上一次发送时间
                        timeoutDuration *= 2;  
                        retryCount++;  
                    }
                    else
                    {
                        // 重传数据包
                        sendto(socketClient, buffer, sizeof(packet) + data_len, 0, (sockaddr*)&servAddr, servAddrlen);
                        lastSendTime = clock();  
                        timeoutDuration *= 2;  
                        retryCount++;  
                    }
                    
                }
            }

            // 检查确认包的正确性
            memcpy(&packet, buffer, sizeof(packet));
            if (packet.ack == (Seq_num + 1) % (256) && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
                cout << "成功发送并接收到确认响应  Ack：" << int(packet.ack) << endl;
            }
            else {
                // 服务端未接受到数据-重传数据（还是上一个数据包）
                if (packet.ack == Seq_num || (compute_sum((WORD*)&packet, sizeof(packet)) != 0)) {
                    cout << "服务端未接受到数据，正在重传！" << endl;
                    i--;
                    continue;
                }
                // 服务端接收到的数据-校验和出错 需要重传
                else {
                    throw runtime_error("客户端未成功接收数据或数据校验失败，需要重传");
                }
            }

            Seq_num = (Seq_num + 1) % 256;  // 更新序列号
        }

        // 数据包发送结束，发送结束标志
        packet.tag = OVER;
        char* buffer = new char[sizeof(packet)];
        packet.checksum = 0;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer, &packet, sizeof(packet));
        sendto(socketClient, buffer, sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
        cout << "已发送数据传输结束标志" << endl;

        int retryCount = 0;
        int timeoutDuration = 1;  // 初始超时时间为1秒
        clock_t start = clock();  // 记录发送时间

        // 等待结束标志的确认
        while (recvfrom(socketClient, buffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
            if ((clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                if (retryCount >= MAX_RETRY_COUNT) {
                    throw runtime_error("结束标志重传失败超过最大尝试次数，错误码：" + to_string(WSAGetLastError()));
                }
                // 超时重传
                sendto(socketClient, buffer, sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
                cout << "结束标志第 " << retryCount + 1 << " 次重传！" << endl;
                start = clock();  
                timeoutDuration *= 2;  
                retryCount++;  
            }
        }

        memcpy(&packet, buffer, sizeof(packet));
        if (packet.tag == OVER && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            cout << "成功接收到结束标志的确认" << endl;
        }
        else {
            throw runtime_error("未能成功接收到结束标志的确认");
        }
    }
    catch (const runtime_error& e)
    {
        cout << "异常发生: " << e.what() << endl;
        mode = 0;
        ioctlsocket(socketClient, FIONBIO, &mode);  // 恢复阻塞模式
        return;
    }
    mode = 0;
    ioctlsocket(socketClient, FIONBIO, &mode);  // 阻塞模式
    return;
}

// 接收数据
// 参数：socketServer - 服务器端的套接字，clieAddr - 客户端地址的结构，clieAddrlen - 客户端地址结构的长度
// Mes - 存储接收到的数据的缓冲区， MAX_SIZE - 每个数据包的最大大小
int RecvMessage(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen, char* Mes, int MAX_SIZE)
{
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet) + MAX_SIZE]);
    int ack = 1;  // 确认序列号
    int seq = 0;
    long FileLength = 0;     // 数据总长
    int SegmentLength = 0;      // 单次数据长度

    try {
        // 循环接收数据
        while (1) {
            // 接收数据
            while (recvfrom(socketServer, buffer.get(), sizeof(packet) + MAX_SIZE, 0, (sockaddr*)&clieAddr, &clieAddrlen) <= 0);
            memcpy(&packet, buffer.get(), sizeof(packet));

            // 检查是否是全局结束标志
            if (packet.tag == END && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
                cout << "已接收到全局结束标志" << endl;
                return 999;
            }

            // 检查是否是数据传输结束标志
            if (packet.tag == OVER && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
                cout << "已接收到数据传输结束标志" << endl;
                break;
            }

            // 处理正常数据包
            if (packet.tag == 0 && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
                // 检查序列号，确认数据包的顺序
                if (packet.seq != seq) {
                    // 如果序列号不匹配，请求重传
                    Packet_Header temp;
                    temp.tag = 0;
                    temp.ack = seq;
                    temp.checksum = 0;
                    temp.checksum = compute_sum((WORD*)&temp, sizeof(temp));
                    memcpy(buffer.get(), &temp, sizeof(temp));
                    sendto(socketServer, buffer.get(), sizeof(temp), 0, (sockaddr*)&clieAddr, clieAddrlen);
                    cout << "已发送重发请求给客户端" << endl;
                    continue;// 继续等待下一个数据包
                }
                // 接收数据
                SegmentLength = packet.datasize;
                cout << "开始接收消息...... 数据大小：" << SegmentLength << " 字节！" << " Tag："
                    << int(packet.tag) << " Seq：" << int(packet.seq) << " CheckSum：" << int(packet.checksum) << endl;
                memcpy(Mes + FileLength, buffer.get() + sizeof(packet), SegmentLength);
                FileLength += SegmentLength;// 更新接收数据总长度
                // 发送确认回复
                packet.tag = 0;
                packet.ack = ack++;
                packet.seq = seq++;
                packet.datasize = 0;
                packet.checksum = 0;
                packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
                memcpy(buffer.get(), &packet, sizeof(packet));
                sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen);
                cout << "成功接收并回送确认  确认号：" << int(packet.ack) << endl;
                // 处理序列号和确认号的循环
                seq = (seq > 255 ? seq - 256 : seq);
                ack = (ack > 255 ? ack - 256 : ack);
            }
        }
        // 发送数据传输结束标志
        packet.tag = OVER;
        packet.checksum = 0;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen);
        cout << "已发送数据传输结束标志" << endl;
    }
    catch (const runtime_error& e) {
        cout << "异常发生: " << e.what() << endl;
        return -1;
    }

    return FileLength;  // 返回接收到的数据总长度
}

int main()
{
    // 初始化Winsock
    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;
    int err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        cout << "Winsock 初始化失败！" << endl;
        return 1;
    }

    // 创建UDP套接字
    SOCKET client = socket(AF_INET, SOCK_DGRAM, 0);
    if (client == INVALID_SOCKET)
    {
        cout << "套接字创建失败，错误码：" << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }
    cout << "客户端套接字创建成功。" << endl;

    // 设置服务器地址
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));// 初始化服务器地址结构体
    serveraddr.sin_family = AF_INET;// 设置协议族为IPv4
    serveraddr.sin_port = htons(PORT);// 设置服务器端口
    inet_pton(AF_INET, IP, &serveraddr.sin_addr.s_addr);// 设置服务器IP地址
    
    // 选择操作模式
    cout << "请选择操作模式（发送0 / 接收1）：" << endl;
    int label;
    cin >> label;

    // 连接到服务器
    int length = sizeof(serveraddr);
    cout << "正在向服务器发起连接请求..." << endl;
    if (Client_Server_Connect(client, serveraddr, length, label) == -1)
    {
        cout << "连接建立失败。" << endl;
        closesocket(client);
        WSACleanup();
        return 1;
    }

    if (label == 0)// 发送模式
    {
        while (true)
        {
            cout << "=====================================================================" << endl;
            cout << "请选择要发送的文件（输入 'q' 退出）：" << endl;
            char InFileName[20];
            cout << "输入文件名：";
            cin >> InFileName;

            // 如果输入'q'，退出
            if (InFileName[0] == 'q' && strlen(InFileName) == 1)
            {
                // 向服务器发送结束标志
                Packet_Header packet;
                char buffer[sizeof(packet)];
                packet.tag = END;
                packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
                memcpy(buffer, &packet, sizeof(packet));
                sendto(client, buffer, sizeof(packet), 0, (sockaddr*)&serveraddr, length);
                cout << "已向服务器发送结束标志。" << endl;
                break;
            }
            // 以二进制模式打开名为 InFileName 的文件，file 用于后续的文件读取操作。
            ifstream file(InFileName, ifstream::binary);
            if (!file)
            {
                cout << "文件打开失败！" << endl;
                continue;
            }

            // 读取文件内容
            file.seekg(0, file.end);// 将文件指针移动到文件的末尾
            int F_length = file.tellg();// 获取当前文件指针的位置，即文件的大小
            file.seekg(0, file.beg);// 重新将文件指针移动到文件的开始处
            unique_ptr<char[]> FileBuffer(new char[F_length]);// 创建一个足够大的缓冲区来存储整个文件的内容
            file.read(FileBuffer.get(), F_length);// 从文件中读取 F_length 字节的数据到缓冲区

            cout << "文件数据大小：" << F_length << " 字节。" << endl;
            // 发送文件名到服务器
            SendMessage(client, serveraddr, length, InFileName, strlen(InFileName), DEFAULT_BUFFER_SIZE);
            clock_t start = clock();
            // 发送文件内容到服务器
            SendMessage(client, serveraddr, length, FileBuffer.get(), F_length, DEFAULT_BUFFER_SIZE);
            clock_t end = clock();

            cout << "设置的丢包率: " << PACKET_LOSS_RATE * 100 << "%" << endl;
            cout << "设置的延时: " << PACKET_DELAY_MS << " 毫秒" << endl;

            cout << "传输总时长：" << (end - start) / CLOCKS_PER_SEC << " 秒。" << endl;
            cout << "吞吐率：" << static_cast<float>(F_length) / ((end - start) / CLOCKS_PER_SEC) << " 字节/秒。" << endl;
            cout << "=====================================================================" << endl;
        }
    }
    else
    {
        while (true)
        {
            cout << "=====================================================================" << endl;
            cout << "等待接收数据..." << endl;
            unique_ptr<char[]> F_name(new char[20]);
            unique_ptr<char[]> Message(new char[100000000]);

            int name_len = RecvMessage(client, serveraddr, length, F_name.get(), DEFAULT_BUFFER_SIZE);
            // 如果接收到的数据长度为999，则跳出循环
            if (name_len == 999)
                break;
            // 接收文件内容
            int file_len = RecvMessage(client, serveraddr, length, Message.get(), DEFAULT_BUFFER_SIZE);
            string fileName(F_name.get(), name_len);
            cout << "接收的文件名：" << fileName << endl;
            cout << "接收的文件数据大小：" << file_len << " 字节。" << endl;
            // 保存文件
            ofstream file(fileName, ofstream::binary);
            if (!file)
            {
                cout << "文件打开失败！" << endl;
                continue;
            }
            file.write(Message.get(), file_len);
            file.close();

            cout << "数据接收完毕，文件已保存。" << endl;
            cout << "=====================================================================" << endl;
        }
    }
    // 断开连接
    Client_Server_Disconnect(client, serveraddr, length);
    // 确保所有数据都被发送
    this_thread::sleep_for(chrono::milliseconds(500));
    closesocket(client);
    WSACleanup();
    cout << "程序已结束。" << endl;
    system("pause");
    return 0;
}