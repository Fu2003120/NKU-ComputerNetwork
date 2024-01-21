/*功能包括：建立连接、差错检测、确认重传等。流量控制采用停等机制*/

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string.h>
#include <string>
#include <fstream>
#include <chrono>
#pragma comment(lib, "ws2_32.lib")
using namespace std;

#define PORT 8888
#define IP "127.0.0.1"
#define DEFAULT_BUFFER_SIZE  1024
const int MAX_RETRY_COUNT = 10;
const BYTE SYN = 0x1;		//SYN = 1 ACK = 0 FIN = 0
const BYTE ACK = 0x2;		//SYN = 0 ACK = 1 FIN = 0
const BYTE ACK_SYN = 0x3;	//SYN = 1 ACK = 1 FIN = 0
const BYTE FIN = 0x4;		//FIN = 1 ACK = 0 SYN = 0
const BYTE FIN_ACK = 0x6;	//FIN = 1 ACK = 1 SYN = 0
const BYTE OVER = 0x8;		//结束标志
const BYTE END = 0x16;		//全局结束标志


struct Packet_Header
{
    WORD datasize;		// 数据长度
    BYTE tag;			// 标签
    //八位，使用后四位，排列是OVER FIN ACK SYN 
    BYTE window;		// 窗口大小
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

// 计算校验和的函数
WORD compute_sum(WORD* message, int size) {   // size = 8
    int count = (size + 1) / 2;  // 防止奇数字节数 确保WORD 16位
    WORD* buf = (WORD*)malloc(size + 1);  // 额外多一个字节用于奇数字节的情况

    memset(buf, 0, size + 1);  // 将所有字节设置为0
    memcpy(buf, message, size);   // 将原始数据复制到新分配的缓冲区

    // 用来累加校验和的变量
    u_long sum = 0;

    // 遍历每个WORD，进行累加
    while (count--) {
        sum += *buf++;

        // 如果累加结果超过16位，将高位加到低位
        if (sum & 0xffff0000) {
            sum &= 0xffff;  // 保留低16位
            sum++;          // 将溢出的高位加到低位
        }
    }

    // 取反操作，生成最终的校验和
    return ~(sum & 0xffff);
}

// 客户端与服务端建立连接（采取三次握手的方式）
// 参数：socketServer - 服务端套接字，clieAddr - 客户端地址，clieAddrlen - 客户端地址长度
int Client_Server_Connect(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen)
{
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
                cout << "成功接收第一次握手信息! " << endl;
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
        cout << "初始的超时时间: " << timeoutDuration << " 秒" << endl;

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
                cout << "超时，正在重传ACK" << endl;
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

        cout << "样本RTT: " << sampleRTT << " 秒" << endl;
        cout << "估计RTT: " << estimatedRTT << " 秒" << endl;
        cout << "RTT偏差: " << devRTT << " 秒" << endl;
        cout << "更新后的超时时间: " << timeoutDuration << " 秒" << endl;

        // 恢复为阻塞模式
        mode = 0;
        ioctlsocket(socketServer, FIONBIO, &mode);

        cout << "成功发送第二次握手信息" << endl;

        // 检查接收到的ACK_SYN包是否正确
        memcpy(&packet, buffer.get(), sizeof(packet));
        if (!(packet.tag == ACK_SYN && (compute_sum((WORD*)&packet, sizeof(packet)) == 0))) {
            throw runtime_error("无法接收客户端回传建立可靠连接，错误码：" + to_string(WSAGetLastError()));
        }
        cout << "成功收到第三次握手信息" << endl;
        cout << "客户端与服务端成功进行三次握手建立连接！可以开始发送/接收数据" << endl;
    }
    catch (const runtime_error& e) {
        cout << "异常发生: " << e.what() << endl;
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
                cout << "服务端成功接收到客户端的第一次挥手信息(FIN_ACK)" << endl;
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
        cout << "服务端成功发送第二次挥手信息(ACK)" << endl;

        // 服务端处理未发送完的数据（如果有的话）

        // 第三次：服务端向客户端发送挥手信息（FIN_ACK）
        packet.tag = FIN_ACK;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen) == -1) {
            throw runtime_error("服务端发送FIN_ACK失败，错误码：" + to_string(WSAGetLastError()));
        }
        cout << "服务端成功发送第三次挥手信息(FIN_ACK)" << endl;

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
                    cout << "等待第三次挥手超时，正在进行第 " << retryCount << " 次重传" << endl;
                    start = clock(); // 重置计时器
                    timeoutDuration *= 2; // 指数退避
                }
            }
            else
            {
                cout << "服务端成功收到客户端的第四次挥手信息(ACK)" << endl;
                cout << "客户端与服务端成功断开连接！" << endl;
                break;
            }
        }
    }
    catch (const runtime_error& e) {
        cout << "断开连接过程中发生异常: " << e.what() << endl;
        return -1;
    }

    return 1;
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

// 发送数据（这里没有丢包、延时和超时超时重传测试）
// socketClient - 客户端的套接字，servAddr - 服务器的地址信息，servAddrlen - 服务器地址信息的长度，
// Message - 要发送的消息的指针，mes_size - 消息的大小，MAX_SIZE - 每个数据包的最大大小
void SendMessage(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, char* Message, int mes_size, int MAX_SIZE)
{
    int packet_num = mes_size / (MAX_SIZE)+(mes_size % MAX_SIZE != 0);// 计算需要的数据包数量
    int Seq_num = 0;  //初始化序列号
    Packet_Header packet;
    u_long mode = 1;
    ioctlsocket(socketClient, FIONBIO, &mode);  // 非阻塞模式

    try
    {
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

            // 发送数据
            sendto(socketClient, buffer, sizeof(packet) + data_len, 0, (sockaddr*)&servAddr, servAddrlen);
            cout << "开始发送消息...... 数据大小：" << data_len << " 字节！" << " Tag：" << int(packet.tag) << " Seq：" << int(packet.seq) << " CheckSum：" << int(packet.checksum) << endl;

            int retryCount = 0;
            int timeoutDuration = 1;  // 初始超时时间为1秒
            clock_t start = clock();  // 记录发送时间

            // 等待确认响应
            while (recvfrom(socketClient, buffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
                if ((clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                    if (retryCount >= MAX_RETRY_COUNT) {
                        throw runtime_error("重传次数超过限制，错误码：" + to_string(WSAGetLastError()));
                    }
                    // 超时重传
                    sendto(socketClient, buffer, sizeof(packet) + data_len, 0, (sockaddr*)&servAddr, servAddrlen);
                    cout << "第 " << retryCount + 1 << " 次重传！" << endl;
                    start = clock();  // 重置计时器
                    timeoutDuration *= 2;  // 指数退避，超时时间加倍
                    retryCount++;  // 增加重传次数
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

        //发送结束标志
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
                retryCount++;
                if (retryCount > MAX_RETRY_COUNT) {
                    throw runtime_error("服务端重传次数超过限制，错误码：" + to_string(WSAGetLastError()));
                }
                // 超时重传
                cout << "服务端等待第四次挥手信息超时，正在进行第 " << retryCount << " 次重传" << endl;
                // 重传逻辑（如有需要）
                start = clock();  // 重置计时器
                timeoutDuration *= 2;  // 指数退避，超时时间加倍
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
    SOCKET server = socket(AF_INET, SOCK_DGRAM, 0);
    if (server == SOCKET_ERROR)
    {
        cout << "套接字创建失败，错误码：" << WSAGetLastError() << endl;
        WSACleanup();
        return 0;
    }
    cout << "服务端套接字创建成功" << endl;

    // 设置服务器地址
    SOCKADDR_IN addr;
    memset(&addr, 0, sizeof(sockaddr_in)); // 初始化地址结构
    addr.sin_family = AF_INET; // 设置地址类型为IPv4
    addr.sin_port = htons(PORT); // 设置端口
    inet_pton(AF_INET, IP, &addr.sin_addr.s_addr); // 设置IP地址
    
    // 绑定套接字
    if (bind(server, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        cout << "绑定失败，错误码：" << WSAGetLastError() << endl;
        WSACleanup();
        return 0;
    }

    // 等待客户端连接
    int length = sizeof(addr);
    cout << "等待客户端连接请求..." << endl;
    int label = Client_Server_Connect(server, addr, length);

    if (label == 0) { //接收数据
        while (true) {
            cout << "=====================================================================" << endl;
            cout << "等待接收数据..." << endl;

            unique_ptr<char[]> F_name(new char[20]);
            unique_ptr<char[]> Message(new char[100000000]);
            int name_len = RecvMessage(server, addr, length, F_name.get(), DEFAULT_BUFFER_SIZE);

            if (name_len == 999) { // 检查是否是结束标志
                cout << "接收到全局结束标志，退出接收循环" << endl;
                break;
            }

            int file_len = RecvMessage(server, addr, length, Message.get(), DEFAULT_BUFFER_SIZE); // 接收文件内容
            string filename(F_name.get(), name_len); // 构造文件名字符串
            cout << "接收到的文件名：" << filename << endl;
            cout << "接收到的文件大小：" << file_len << " 字节" << endl;

            ofstream file_stream(filename, ios::binary); // 创建文件流
            if (!file_stream) { // 检查文件是否打开成功
                cout << "文件打开失败" << endl;
                continue; // 打开失败，继续下一轮循环
            }

            file_stream.write(Message.get(), file_len);// 写入文件内容
            cout << "数据接收完毕，文件已保存" << endl;
            cout << "=====================================================================" << endl;
        }
    }
    else if (label == 1) { // 发送数据
        while (true) {
            cout << "=====================================================================" << endl;
            cout << "选择要发送的文件..." << endl;

            char InFileName[20];
            cout << "输入文件名（输入 'q' 退出）:";
            cin >> InFileName;

            if (strcmp(InFileName, "q") == 0) { // 检查是否输入退出指令
                Packet_Header packet;
                unique_ptr<char[]> buffer(new char[sizeof(packet)]); // 创建缓冲区
                packet.tag = END; // 设置结束标志
                packet.checksum = compute_sum((WORD*)&packet, sizeof(packet)); // 计算校验和
                memcpy(buffer.get(), &packet, sizeof(packet)); // 复制到缓冲区
                sendto(server, buffer.get(), sizeof(packet), 0, (sockaddr*)&addr, length); // 发送结束标志
                cout << "发送全局结束标志至服务器" << endl;
                break; // 退出循环
            }

            ifstream file_stream(InFileName, ios::binary | ios::ate); // 打开文件
            if (!file_stream) { // 检查文件是否打开成功
                cout << "文件打开失败" << endl;
                continue; // 打开失败，继续下一轮循环
            }

            int F_length = static_cast<int>(file_stream.tellg()); // 获取文件大小
            file_stream.seekg(0, ios::beg); // 重置文件指针
            unique_ptr<char[]> FileBuffer(new char[F_length]); // 创建文件内容缓冲区
            file_stream.read(FileBuffer.get(), F_length); // 读取文件内容

            cout << "发送文件数据大小：" << F_length << " 字节" << endl;

            SendMessage(server, addr, length, InFileName, strlen(InFileName), DEFAULT_BUFFER_SIZE); // 发送文件名
            clock_t start = clock(); // 记录开始时间
            SendMessage(server, addr, length, FileBuffer.get(), F_length, DEFAULT_BUFFER_SIZE); // 发送文件内容
            clock_t end = clock(); // 记录结束时间
            cout << "传输总用时：" << static_cast<double>(end - start) / CLOCKS_PER_SEC << " 秒" << endl;
            cout << "吞吐率：" << static_cast<double>(F_length) / ((end - start) / CLOCKS_PER_SEC) << " 字节/秒" << endl;
            cout << "=====================================================================" << endl;
        }
    }

    // 断开连接并清理资源
    Client_Server_Disconnect(server, addr, length); // 断开连接
    closesocket(server); // 关闭套接字
    WSACleanup(); // 清理Winsock
    cout << "程序已结束。" << endl;
    system("pause"); 
    return 0;
}
