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
#define DEFAULT_WINDOW_SIZE  8
const int MAX_RETRY_COUNT = 25;
const BYTE SYN = 0x1;		//SYN = 1 ACK = 0 FIN = 0
const BYTE ACK = 0x2;		//SYN = 0 ACK = 1 FIN = 0
const BYTE ACK_SYN = 0x3;	//SYN = 1 ACK = 1 FIN = 0

const BYTE FIN = 0x4;		//FIN = 1 ACK = 0 SYN = 0
const BYTE FIN_ACK = 0x6;	//FIN = 1 ACK = 1 SYN = 0
const BYTE OVER = 0x8;		//������־
const BYTE END = 0x16;		//ȫ�ֽ�����־


struct Packet_Header
{
    WORD datasize;		// ���ݳ���
    BYTE tag;			// ��ǩ
    //��λ��ʹ�ú���λ��������OVER FIN ACK SYN 
    BYTE window;		// ���ڴ�С
    BYTE seq;			// ���к�
    BYTE ack;			// ȷ�Ϻ�
    WORD checksum;		// У���

    // ��ʼ��
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

// ����У��͵ĺ���
WORD compute_sum(WORD* message, int size) {   // size = 8
    int count = (size + 1) / 2;  // ��ֹ�����ֽ��� ȷ��WORD 16λ
    WORD* buf = (WORD*)malloc(size + 1);  // �����һ���ֽ����������ֽڵ����

    memset(buf, 0, size + 1);  // �������ֽ�����Ϊ0
    memcpy(buf, message, size);   // ��ԭʼ���ݸ��Ƶ��·���Ļ�����

    // �����ۼ�У��͵ı���
    u_long sum = 0;

    // ����ÿ��WORD�������ۼ�
    while (count--) {
        sum += *buf++;

        // ����ۼӽ������16λ������λ�ӵ���λ
        if (sum & 0xffff0000) {
            sum &= 0xffff;  // ������16λ
            sum++;          // ������ĸ�λ�ӵ���λ
        }
    }

    // ȡ���������������յ�У���
    return ~(sum & 0xffff);
}

// �ͻ��������˽������ӣ���ȡ�������ֵķ�ʽ��
// ������socketServer - ������׽��֣�clieAddr - �ͻ��˵�ַ��clieAddrlen - �ͻ��˵�ַ����
int Client_Server_Connect(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen) {
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet)]);  // ʹ������ָ���Զ������ڴ�

    try {
        // ��һ�����֣�����˵ȴ������տͻ��˷��͵�SYN��
        while (true) {
            if (recvfrom(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, &clieAddrlen) == -1) {
                throw runtime_error("�޷����տͻ��˷��͵��������󣬴����룺" + to_string(WSAGetLastError()));
            }
            memcpy(&packet, buffer.get(), sizeof(packet));
            if (packet.tag == SYN && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
                cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
                cout << "\033[32m" << "| �ɹ����յ�һ��������Ϣ |" << "\033[0m" << endl;
                break;
            }
        }

        // Jacobson/Karels�㷨
        // ��ʼ��RTT��ز��������ں����ĳ�ʱ����
        double estimatedRTT = 1.0;  // ��ʼ����RTT
        double devRTT = 0.0;  // ��ʼRTTƫ��
        const double alpha = 0.125;  // ����RTT��Ȩ��
        const double beta = 0.25;  // ƫ���Ȩ��
        double timeoutDuration = estimatedRTT + 4 * devRTT;  // ��ʼ����ʱʱ��

        // �ڶ������֣��������ͻ��˷���ACK����ȷ���յ�SYN��
        packet.tag = ACK;
        packet.checksum = 0;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen) == -1) {
            throw runtime_error("����ACKʧ�ܣ������룺" + to_string(WSAGetLastError()));
        }

        // ���÷�����ģʽ�����ڳ�ʱ���
        u_long mode = 1;
        ioctlsocket(socketServer, FIONBIO, &mode);
        clock_t start = clock();  // ��¼��ʼ�ȴ�ACK_SYN����ʱ��

        // ���������֣�����˵ȴ��ͻ��˷���ACK_SYN��
        while (recvfrom(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, &clieAddrlen) <= 0) {
            // ����Ƿ�ʱ������ǣ����ط�ACK��
            if (double(clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                cout << "\033[34m" << "��ʱ�������ش�ACK" << "\033[0m" << endl;
                if (sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen) == -1) {
                    throw runtime_error("�ش�ACKʧ�ܣ������룺" + to_string(WSAGetLastError()));
                }
                start = clock();  // ���ü�ʱ��
                timeoutDuration = estimatedRTT + 4 * devRTT;  // ����RTT�Ķ�̬������ʱʱ��
            }
        }

        // ����RTT����
        double sampleRTT = double(clock() - start) / CLOCKS_PER_SEC;
        estimatedRTT = (1 - alpha) * estimatedRTT + alpha * sampleRTT;
        devRTT = (1 - beta) * devRTT + beta * abs(sampleRTT - estimatedRTT);
        timeoutDuration = estimatedRTT + 4 * devRTT;  // ���³�ʱʱ��

        // �ָ�Ϊ����ģʽ
        mode = 0;
        ioctlsocket(socketServer, FIONBIO, &mode);

        cout << "\033[32m" << "| �ɹ����͵ڶ���������Ϣ |" << "\033[0m" << endl;

        // �����յ���ACK_SYN���Ƿ���ȷ
        memcpy(&packet, buffer.get(), sizeof(packet));
        if (!(packet.tag == ACK_SYN && (compute_sum((WORD*)&packet, sizeof(packet)) == 0))) {
            throw runtime_error("�޷����տͻ��˻ش������ɿ����ӣ������룺" + to_string(WSAGetLastError()));
        }
        cout << "\033[32m" << "| �ɹ����յ�����������Ϣ |" << "\033[0m" << endl;
        cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
    }
    catch (const runtime_error& e) {
        cout << "\033[31m" << "�쳣����: " << e.what() << "\033[0m" << endl;
        return -1;
    }

    return int(packet.datasize);  // �������ݰ���С
}

// �ͻ��������˶Ͽ����ӣ���ȡ�Ĵλ��ֵķ�ʽ��
// ������socketServer - ������׽��֣�clieAddr - �ͻ��˵�ַ��clieAddrlen - �ͻ��˵�ַ����
int Client_Server_Disconnect(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen) {
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet)]);  // ʹ������ָ���Զ������ڴ�

    try {
        // ���տͻ��˷����ĵ�һ�λ�����Ϣ��FIN_ACK��
        while (true) {
            // �������ݰ�
            if (recvfrom(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, &clieAddrlen) == -1) {
                throw runtime_error("�޷����տͻ��˷��͵Ļ������󣬴����룺" + to_string(WSAGetLastError()));
            }

            // ����Ƿ�ΪFIN_ACK��־�����ݰ�
            memcpy(&packet, buffer.get(), sizeof(packet));
            if (packet.tag == FIN_ACK && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
                cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
                cout << "\033[32m" << "| �ɹ����յ�һ�λ�����Ϣ |" << "\033[0m" << endl;
                break;
            }
        }

        // �ڶ��Σ��������ͻ��˷��ͻ�����Ϣ��ACK��
        packet.tag = ACK;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen) == -1) {
            throw runtime_error("����˷���ACKʧ�ܣ������룺" + to_string(WSAGetLastError()));
        }
        cout << "\033[32m" << "| �ɹ����͵ڶ��λ�����Ϣ |" << "\033[0m" << endl;

        // ����˴���δ����������ݣ�����еĻ���

        // �����Σ��������ͻ��˷��ͻ�����Ϣ��FIN_ACK��
        packet.tag = FIN_ACK;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen) == -1) {
            throw runtime_error("����˷���FIN_ACKʧ�ܣ������룺" + to_string(WSAGetLastError()));
        }
        cout << "\033[32m" << "| �ɹ����͵����λ�����Ϣ |" << "\033[0m" << endl;

        clock_t start = clock();  // ��¼����ʱ��
        int retryCount = 0;       // �ش�����
        int timeoutDuration = 1;  // ��ʼ��ʱʱ��Ϊ1��

        // ���Ĵλ��֣�����˽��տͻ��˷��͵�ACK
        while (true)
        {
            if (recvfrom(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, &clieAddrlen) <= 0) {
                // �����ʱ���������Ҫ�ش�FIN_ACK
                if ((clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                    retryCount++;
                    if (retryCount > MAX_RETRY_COUNT) {
                        throw runtime_error("���Ĵλ����ش������������ƣ������룺" + to_string(WSAGetLastError()));
                    }
                    cout << "\033[34m" << "�ȴ������λ��ֳ�ʱ�����ڽ��е� " << retryCount << " ���ش�" << "\033[0m" << endl;
                    start = clock(); // ���ü�ʱ��
                    timeoutDuration *= 2; // ָ���˱�
                }
            }
            else
            {
                cout << "\033[32m" << "| �ɹ����յ��Ĵλ�����Ϣ |" << "\033[0m" << endl;
                cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
                cout << "\033[32m" << "�ͻ��������˳ɹ��Ͽ����ӣ�" << "\033[0m" << endl;
                break;
            }
        }
    }
    catch (const runtime_error& e) {
        cout << "\033[31m" << "�Ͽ����ӹ����з����쳣: " << e.what() << "\033[0m" << endl;
        return -1;
    }

    return 1;
}

// ��������
// ������socketServer - �������˵��׽��֣�clieAddr - �ͻ��˵�ַ�Ľṹ��clieAddrlen - �ͻ��˵�ַ�ṹ�ĳ���
// Mes - �洢���յ������ݵĻ������� MAX_SIZE - ÿ�����ݰ�������С
int RecvMessage(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen, char* Message, int MAX_SIZE, int Window) {
    Packet_Header packet;
    char* receiveBuffer = new char[sizeof(packet) + MAX_SIZE];  // ���ջ�����
    int Ack_num = 1;  // ȷ�����к�
    int Seq_num = 0;  // ���к�
    long totalDataLength = 0;     // ���յ��������ܳ���
    int singleDataLength = 0;     // ���ν��յ����ݳ���
    bool timeoutTestFlag = true;  // ��ʱ���Ա�־


    // ѭ����������
    while (true)
    {
        while (recvfrom(socketServer, receiveBuffer, sizeof(packet) + MAX_SIZE, 0, (sockaddr*)&clieAddr, &clieAddrlen) <= 0);
        memcpy(&packet, receiveBuffer, sizeof(packet));

        // �����ʱ�ش�����
        /*
        if (((rand() % (255 - 1)) + 1) == 199 && timeoutTestFlag) {
            cout << endl << "\033[34m[TEST] \033[0m �����ʱ�ش����Դ��� - Seq��" << int(packet.seq) << endl;
            timeoutTestFlag = false;
            continue;
        }
        */

        // �յ�ȫ�ֽ������
        if (packet.tag == END && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            cout << "\033[32m[INFO]\033[0m ȫ�ֽ�����־�ѽ���" << endl;
            return 999;
        }

        // �յ��������ݰ����ͽ������
        if (packet.tag == OVER && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            cout << "\033[32m[INFO]\033[0m ������־�ѽ���" << endl;
            break;
        }

        // ��������
        if (packet.tag == 0 && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            // ������յ������кŲ���Ԥ�ڵģ������ش�����
            if (packet.seq != Seq_num) {
                Packet_Header resendHeader;
                resendHeader.tag = 0;
                resendHeader.ack = Ack_num - 1;  // �ۼ�ȷ�ϣ�������һ��ȷ�ϵ�ACK
                resendHeader.checksum = 0;
                resendHeader.checksum = compute_sum((WORD*)&resendHeader, sizeof(resendHeader));
                memcpy(receiveBuffer, &resendHeader, sizeof(resendHeader));
                sendto(socketServer, receiveBuffer, sizeof(resendHeader), 0, (sockaddr*)&clieAddr, clieAddrlen);
                cout << "\033[31m[ERROR]\033[0m ���кŴ��� - ��ͻ��˷����ش����� - Ack" << int(packet.ack) << endl;
                continue;
            }

            // �ɹ���������
            singleDataLength = packet.datasize;
            cout << "\033[32m[INFO]\033[0m �������ݰ� - ���ݴ�С: " << singleDataLength << " �ֽ�, Tag: " << int(packet.tag) << ", Seq��" << int(packet.seq) << ", CheckSum: " << int(packet.checksum) << endl;
            memcpy(Message + totalDataLength, receiveBuffer + sizeof(packet), singleDataLength);
            totalDataLength += singleDataLength;

            // ȷ�Ͻ��ճɹ�������ACK
            packet.tag = 0;
            packet.ack = Ack_num++;
            packet.seq = Seq_num++;
            Seq_num = (Seq_num > 255 ? Seq_num - 256 : Seq_num);
            Ack_num = (Ack_num > 255 ? Ack_num - 256 : Ack_num);
            packet.datasize = 0;
            packet.checksum = 0;
            packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
            memcpy(receiveBuffer, &packet, sizeof(packet));

            /*
            if (((rand() % (255 - 1)) + 1) != 187) {
                sendto(socketServer, receiveBuffer, sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen);
                cout << "\033[32m[INFO]\033[0m �ɹ�����ACK��Ӧ - Seq: " << int(packet.seq) << ", Ack: " << int(packet.ack) << endl;
            }
            else {
                cout << "\033[34m[TEST]\033[0m �ۼ�ȷ�ϲ��Դ��� - ���к�: " << int(packet.seq) << ", δ����ACK" << endl;
            }
            */
            sendto(socketServer, receiveBuffer, sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen);

            cout << "\033[32m[INFO]\033[0m �ɹ��������� - Seq: " << int(packet.seq) << ", ���ݴ�С: " << singleDataLength << " �ֽ�" << endl;
        }
        else if (packet.tag == 0) {  // ����У��ʧ�ܣ������ش�
            Packet_Header resendHeader;
            resendHeader.tag = 0;
            resendHeader.ack = Ack_num - 1;  // ������һ��ȷ�ϵ�ACK
            resendHeader.checksum = 0;
            resendHeader.checksum = compute_sum((WORD*)&resendHeader, sizeof(resendHeader));
            memcpy(receiveBuffer, &resendHeader, sizeof(resendHeader));

            sendto(socketServer, receiveBuffer, sizeof(resendHeader), 0, (sockaddr*)&clieAddr, clieAddrlen);

            cout << "\033[31m[ERROR]\033[0m ����У��ʧ�� - ���Ͷ˷������һ��ȷ�ϵ�ACK��Ack:" << int(packet.ack) << endl;
            continue;
        }
    }

    // ���ͽ�����־
    packet.tag = OVER;
    packet.checksum = 0;
    packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
    memcpy(receiveBuffer, &packet, sizeof(packet));
    sendto(socketServer, receiveBuffer, sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen);
    cout << "\033[32m[INFO]\033[0m ������־�ѷ���" << endl;
    delete[] receiveBuffer;
    return totalDataLength;
}

// ��������
// socketClient - �ͻ��˵��׽��֣�servAddr - �������ĵ�ַ��Ϣ��servAddrlen - ��������ַ��Ϣ�ĳ��ȣ�
// Message - Ҫ���͵���Ϣ��ָ�룬mes_size - ��Ϣ�Ĵ�С��MAX_SIZE - ÿ�����ݰ�������С��Window - �������ڴ�С
void SendMessage(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, char* Message, int mes_size, int MAX_SIZE, int Window) {
    int totalPacketCount = mes_size / (MAX_SIZE)+(mes_size % MAX_SIZE != 0);    // �������ݰ�����
    int BaseIndex = -1;                                                         // ��������� [0,totalPacketCount]
    int NextSeqNum = 0;                                                         // ��һ��Ҫ�������ݰ������� [0,totalPacketCount]
    int lastUnacknowledgedPacketIndex = 0;                                      // ���緢����δ�յ�ȷ�ϵ����ݰ������� [0,totalPacketCount]
    int Seq_num = 0;                                                            // ���к� [0,255]
    int Ack_num = 1;                                                            // ȷ�Ϻ� [0,255]

    Packet_Header packet;

    // ���������ݴ���
    char** stagingBuffer = new char* [Window];                                  // ���ͻ�����
    int* stagingBufferLengths = new int[Window];                                // ��������ÿ�����ݰ�����
    for (int i = 0; i < Window; i++) {
        stagingBuffer[i] = new char[sizeof(packet) + MAX_SIZE];                 // ��ʼ���ڴ�
    }

    // ����Ϊ������ģʽ
    u_long socketMode = 1;
    ioctlsocket(socketClient, FIONBIO, &socketMode);

    // ��ʼ����ʱ����GBNֻ��Ҫ����һ����ʱ����
    clock_t timerStart = 0;
    bool timerRunning = false;

    // �����������ݰ�
    while (BaseIndex < (totalPacketCount - 1)) {
        /*
        ���ͻ��������������ݰ���1.�ڷ��ͻ�������2.û�г�������

        BaseIndex   NextSeqNum    BaseIndex + Window         totalPacketCount
        +---------------+-----------------+---------- ... ... -----------+
        */
        while (NextSeqNum <= BaseIndex + Window && NextSeqNum < totalPacketCount)
        {
            // ���㵱ǰ���ݰ���С��1.���һ�����ݰ���mes_size - (totalPacketCount - 1) * MAX_SIZE��2.�������ݰ���MAX_SIZE
            int packetDataSize = (NextSeqNum == totalPacketCount - 1 ? mes_size - (totalPacketCount - 1) * MAX_SIZE : MAX_SIZE);
            // �������ݰ�ͷ����Ϣ
            packet.tag = 0;
            packet.seq = Seq_num++;
            Seq_num = (Seq_num > 255 ? Seq_num - 256 : Seq_num);
            packet.datasize = packetDataSize;
            stagingBufferLengths[NextSeqNum % Window] = packetDataSize;         // GBN����������¼��Ӧ���ݰ�����
            packet.window = Window - (NextSeqNum - BaseIndex);                  // ʣ�ര�ڴ�С
            packet.checksum = 0;
            packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));

            // �����ݰ�ͷ���������Ⱥ��Ƶ����ͻ�������������������Window������
            memcpy(stagingBuffer[NextSeqNum % Window], &packet, sizeof(packet));
            char* messageFragment = Message + NextSeqNum * MAX_SIZE;
            memcpy(stagingBuffer[NextSeqNum % Window] + sizeof(packet), messageFragment, packetDataSize);

            // �������ݰ�
            sendto(socketClient, stagingBuffer[NextSeqNum % Window], sizeof(packet) + packetDataSize, 0, (sockaddr*)&servAddr, servAddrlen);

            // ������ʱ��
            if (!timerRunning) {
                timerStart = clock();
                timerRunning = true;
            }

            cout << "\033[32m[INFO]\033[0m �������ݰ� - ���ݴ�С: " << packetDataSize << " �ֽ�, Seq: " << int(packet.seq) << ", WindowSize: " << int(packet.window) << ", CheckSum: " << int(packet.checksum) << ", �׸�δȷ�����ݰ����: " << lastUnacknowledgedPacketIndex << endl;
            NextSeqNum++;
        }

        char* receiveBuffer = new char[sizeof(packet)];  // ���ջ�����

        // δ�յ����ն˻ظ���ȷ����Ϣ
        while (recvfrom(socketClient, receiveBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
            if (timerRunning && (clock() - timerStart) / CLOCKS_PER_SEC > 2) {
                // GBN�����·������һ����ȷ�ϵ����ݰ�֮����������ݰ�
                for (int temp = lastUnacknowledgedPacketIndex; temp < NextSeqNum; temp++) {
                    sendto(socketClient, stagingBuffer[temp % Window], sizeof(packet) + stagingBufferLengths[temp % Window], 0, (sockaddr*)&servAddr, servAddrlen);
                    cout << "\033[31m[WARNING]\033[0m ��ʱ - �ش����ݰ���δȷ�ϰ���ţ�" << temp % Window << endl;
                }
                // ���ö�ʱ��
                timerStart = clock();
            }
        }

        // �յ����ն˻ظ���ȷ����Ϣ
        memcpy(&packet, receiveBuffer, sizeof(packet));

        // У�����ݰ�
        if ((compute_sum((WORD*)&packet, sizeof(packet)) != 0)) {
            continue;
        }

        // �յ����ն˵Ľ���ȷ��
        if (packet.ack == Ack_num) {
            // ����ȷ�Ϻ�
            Ack_num = (Ack_num + 1) % 256;
            cout << "\033[32m[INFO]\033[0m �յ�ȷ�� - Ack: " << int(packet.ack) << endl;
            // GBN����������
            BaseIndex++;
            lastUnacknowledgedPacketIndex++;
            // GBN�����͵��������ݰ�ȫ���յ����ն˵�ȷ�Ϻ�ֹͣ��ʱ��
            if (lastUnacknowledgedPacketIndex == NextSeqNum) {
                timerRunning = false;
            }
        }
        else {
            // ��֤�������к�ѭ���������
            // -  dis > 0������ack���ڵ�ǰack֮�� -> �������
            // - dis <= 0�����кų���ѭ������ǰ ack �� 250�����յ��� ack �� 5��5 Ӧ������ 250 ֮����� -> ���㷽ʽ��Ϊ: (int(packet.ack) + 256 - Ack_num)
            int dis = (int(packet.ack) - Ack_num) > 0 ? (int(packet.ack) - Ack_num) : (int(packet.ack) + 256 - Ack_num);

            // ��⵽�ظ�ȷ��
            if (packet.ack == (Ack_num == 0 ? 255 : Ack_num - 1)) {
                // ���Ack_num��0��ǰһ��ȷ�Ϻ�Ӧ����255���������Ack_num - 1��
                cout << "\033[31m[WARNING]\033[0m �յ��ظ�ȷ�ϣ�Ack: " << int(packet.ack) << endl;
                // ����������ʵ�ֿ����ش����ƣ������Ҫ��
            }
            // ���͵����ݰ����շ��Ѿ����ܣ����ǽ��շ���ȷ����Ϣ��ʧ������Ϊ�յ�������Ack֮���Ack�����ͷ��Ϳ��Լ�������֮ǰ�����ݰ����Ѿ������շ�ȷ��
            // Ŀ���������Ч���Լ��Խ��ն��ۼ�ȷ�ϵ�����
            else if (dis < Window || (Ack_num + dis) % 256 == packet.ack) {  //  (Ack_num + dis) % 256 == packet.ack ��Ϊ�˴���ѭ�������

                cout << endl << "\033[34m[INFO]\033[0m �ۼ�ȷ�ϴ�����" << endl;

                // ���·��Ͷ˵�״̬���ƶ����� + ����������ȷ�Ϻ�
                while (Ack_num != (packet.ack + 1) % 256) {
                    cout << "\033[32m[INFO]\033[0m �ۼ�ȷ�� - Ack: " << Ack_num << endl;
                    BaseIndex++;
                    lastUnacknowledgedPacketIndex = (lastUnacknowledgedPacketIndex + 1) % Window;
                    Ack_num = (Ack_num + 1) % 256;
                }
                cout << "\033[34m[INFO]\033[0m �ۼ�ȷ�ϴ������\n" << endl;

            }
            else {
                // �쳣�����dis ���ڴ��ڴ�С ���� �յ���ACK����ͨ���ۼ�ȷ���߼��������Ԥ��ACK
                // �ط�����δȷ�ϵ����ݰ�
                cout << "\033[31m[WARNING]\033[0m ��⵽У������ACK��������ʼ�ش�δȷ�����ݰ�" << endl;
                for (int temp = BaseIndex + 1; temp <= BaseIndex + Window && temp < totalPacketCount; temp++) {
                    sendto(socketClient, stagingBuffer[temp % Window], sizeof(packet) + stagingBufferLengths[temp % Window], 0, (sockaddr*)&servAddr, servAddrlen);
                    cout << "\033[32m[INFO]\033[0m �ش����ݰ���Seq: " << temp % 256 << endl;
                }
                cout << "\033[32m[INFO]\033[0m �ش��������" << endl;
            }
        }

        // ������ջ�������Դ
        delete[] receiveBuffer;
    }

    // ���ͽ�����־
    packet.tag = OVER;
    char* endSignalBuffer = new char[sizeof(packet)];
    packet.checksum = 0;
    packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
    memcpy(endSignalBuffer, &packet, sizeof(packet));
    sendto(socketClient, endSignalBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
    cout << "\033[32m[INFO]\033[0m ������־�ѷ���" << endl;

    // ȷ�Ͻ�����־�Ľ���
    clock_t endSignalStartTime = clock();
    while (recvfrom(socketClient, endSignalBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
        if ((clock() - endSignalStartTime) / 1000 > 1) {
            sendto(socketClient, endSignalBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
            cout << "\033[31m[WARNING]\033[0m ������־���ͳ�ʱ - �����ش�" << endl;
            endSignalStartTime = clock();
        }
    }

    // �л�������ģʽ
    socketMode = 0;
    ioctlsocket(socketClient, FIONBIO, &socketMode);

    memcpy(&packet, endSignalBuffer, sizeof(packet));
    if (packet.tag == OVER && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
        cout << "\033[32m[INFO]\033[0m �ɹ����յ�������־" << endl;
    }
    else {
        cout << "[ERROR] �޷����տͻ��˻ش��Ľ�����־" << endl;
    }
    return;

    // ��������źŻ�������Դ
    delete[] endSignalBuffer;

    // �����ͻ�������Դ
    for (int i = 0; i < Window; i++) {
        delete[] stagingBuffer[i];
    }
    delete[] stagingBuffer;
    delete[] stagingBufferLengths;
}

int main()
{
    cout << "\033[33m" << "======================= ����ʼ =======================" << "\033[0m" << endl;

    // ��ʼ��Winsock
    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;
    if (WSAStartup(wVersionRequested, &wsaData) != 0)
    {
        cout << "\033[31m" << "Winsock ��ʼ��ʧ�ܣ�" << "\033[0m" << endl;
        return 1;
    }

    // ����UDP�׽���
    SOCKET server = socket(AF_INET, SOCK_DGRAM, 0);
    if (server == SOCKET_ERROR)
    {
        cout << "\033[31m" << "�׽��ִ���ʧ�ܣ������룺" << WSAGetLastError() << "\033[0m" << endl;
        WSACleanup();
        return 0;
    }

    cout << "\033[32m" << "�������׽��ִ����ɹ�" << "\033[0m" << endl;

    // ���÷�������ַ
    SOCKADDR_IN addr;
    memset(&addr, 0, sizeof(sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, IP, &addr.sin_addr.s_addr);

    // ���׽���
    if (bind(server, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        cout << "\033[31m" << "��ʧ�ܣ������룺" << WSAGetLastError() << "\033[0m" << endl;
        closesocket(server);
        WSACleanup();
        return 0;
    }

    // �ȴ��ͻ�������
    int length = sizeof(addr);
    cout << "\033[33m" << "�ȴ��ͻ�����������...\n" << "\033[0m";
    int label = Client_Server_Connect(server, addr, length);

    cout << "\033[33m" << "���ݻ�������С��" << DEFAULT_BUFFER_SIZE << " �������ڻ�������С��" << DEFAULT_WINDOW_SIZE << "\033[33m" << endl;

    if (label == 0) { // ��������
        while (true) {
            cout << "\033[33m" << "======================= �ȴ��������� =======================" << "\033[0m" << endl;

            unique_ptr<char[]> F_name(new char[20]);
            unique_ptr<char[]> Message(new char[100000000]);
            int name_len = RecvMessage(server, addr, length, F_name.get(), DEFAULT_BUFFER_SIZE, DEFAULT_WINDOW_SIZE);

            if (name_len == 999) { // ����Ƿ���ȫ�ֽ�����־
                cout << "\033[32m" << "���յ�ȫ�ֽ�����־���˳�����ѭ��" << "\033[0m" << endl;
                break;
            }

            int file_len = RecvMessage(server, addr, length, Message.get(), DEFAULT_BUFFER_SIZE, DEFAULT_WINDOW_SIZE); // �����ļ�����
            string filename(F_name.get(), name_len); // �����ļ����ַ���
            cout << "\033[32m" << "���յ����ļ�����" << filename << "\033[0m" << endl;
            cout << "\033[32m" << "���յ����ļ���С��" << file_len << "\033[0m" << " �ֽ�" << endl;

            ofstream file_stream(filename, ios::binary); // �����ļ���
            if (!file_stream) { // ����ļ��Ƿ�򿪳ɹ�
                cout << "\033[31m" << "�ļ���ʧ��" << "\033[0m" << endl;
                continue; // ��ʧ�ܣ�������һ��ѭ��
            }

            file_stream.write(Message.get(), file_len);// д���ļ�����
            file_stream.close();

            cout << "\033[32m" << "======================= ���ݽ�����ϣ��ļ��ѱ��� =======================" << "\033[0m" << endl;
        }
    }
    else if (label == 1) { // ��������
        while (true) {
            cout << "\033[33m" << "======================= ѡ��Ҫ���͵��ļ� =======================" << "\033[0m" << endl;
            char InFileName[20];
            cout << "\033[33m" << "�����ļ��������� 'q' �˳���:" << "\033[0m" << endl;
            cin >> InFileName;

            if (strcmp(InFileName, "q") == 0) { // ����Ƿ������˳�ָ��
                Packet_Header packet;
                unique_ptr<char[]> buffer(new char[sizeof(packet)]); // ����������
                packet.tag = END; // ���ý�����־
                packet.checksum = compute_sum((WORD*)&packet, sizeof(packet)); // ����У���
                memcpy(buffer.get(), &packet, sizeof(packet)); // ���Ƶ�������
                sendto(server, buffer.get(), sizeof(packet), 0, (sockaddr*)&addr, length); // ���ͽ�����־
                cout << "\033[32m" << "����ȫ�ֽ�����־���ͻ���" << "\033[0m" << endl;
                break; // �˳�ѭ��
            }

            ifstream file_stream(InFileName, ios::binary | ios::ate); // ���ļ�
            if (!file_stream) { // ����ļ��Ƿ�򿪳ɹ�
                cout << "\033[31m" << "�ļ���ʧ��" << "\033[0m" << endl;
                continue;
            }

            int F_length = static_cast<int>(file_stream.tellg()); // ��ȡ�ļ���С
            file_stream.seekg(0, ios::beg); // �����ļ�ָ��
            unique_ptr<char[]> FileBuffer(new char[F_length]); // �����ļ����ݻ�����
            file_stream.read(FileBuffer.get(), F_length); // ��ȡ�ļ�����

            cout << "\033[32m" << "�����ļ����ݴ�С��" << F_length << " �ֽ�" << "\033[0m" << endl;

            SendMessage(server, addr, length, InFileName, strlen(InFileName), DEFAULT_BUFFER_SIZE, DEFAULT_WINDOW_SIZE); // �����ļ���
            clock_t start = clock(); // ��¼��ʼʱ��
            SendMessage(server, addr, length, FileBuffer.get(), F_length, DEFAULT_BUFFER_SIZE, DEFAULT_WINDOW_SIZE); // �����ļ�����
            clock_t end = clock(); // ��¼����ʱ��
            cout << "\033[33m" << "��������ʱ��" << static_cast<double>(end - start) / CLOCKS_PER_SEC << " ��" << "\033[0m" << endl;
            cout << "\033[33m" << "�����ʣ�" << static_cast<double>(F_length) / ((end - start) / CLOCKS_PER_SEC) << " �ֽ�/��" << "\033[0m" << endl;
            cout << "\033[33m" << "=====================================================================" << "\033[0m" << endl;
        }
    }

    // �Ͽ����Ӳ�������Դ
    Client_Server_Disconnect(server, addr, length); // �Ͽ�����
    closesocket(server);
    WSACleanup();
    cout << "\033[33m" << "======================= ������� =======================" << "\033[0m" << endl;
    system("pause");
    return 0;
}
