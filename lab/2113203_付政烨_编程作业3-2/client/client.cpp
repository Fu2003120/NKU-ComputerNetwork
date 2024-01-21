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
const int MAX_RETRY_COUNT = 10;  // ����ش�����
const BYTE SYN = 0x1;		//��ʼ����������SYN = 1 ACK = 0 FIN = 0
const BYTE ACK = 0x2;		//ȷ���յ���Ϣ��SYN = 0 ACK = 1 FIN = 0
const BYTE ACK_SYN = 0x3;	//ȷ����������SYN = 1 ACK = 1 FIN = 0
const BYTE FIN = 0x4;		//��ʼ��ֹ���ӣ�FIN = 1 ACK = 0 SYN = 0
const BYTE FIN_ACK = 0x6;	//ȷ��������ֹ��FIN = 1 ACK = 1 SYN = 0
const BYTE OVER = 0x8;		//���ݴ������
const BYTE END = 0x16;		//ͨ�Ź���ȫ�ֽ���
int PACKET_DELAY_MS = 1; // ������ʱ

typedef struct Packet_Header
{
    WORD datasize;		// ���ݳ���
    BYTE tag;			// ��ǩ����λ��ʹ�ú���λ��������OVER FIN ACK SYN 
    BYTE window;		// ���ڴ�С��δʹ�ã�
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

// ����У���
WORD compute_sum(WORD* message, int size) {
    // size = 8
    // ���㴦���WORD���������size�����������1��ȷ�����������ֽ�
    int count = (size + 1) / 2;

    // �����㹻���ڴ����洢��Ϣ������Ϊ���ܵĶ����ֽ������ռ�
    WORD* buf = (WORD*)malloc(size + 1);
    // ��ʼ��������ڴ棬ȷ�����һ���ֽڣ�����У�������Ϊ0
    memset(buf, 0, size + 1);
    // ��ԭʼ��Ϣ���Ƶ��·���Ļ�������
    memcpy(buf, message, size);

    u_long sum = 0; // �����ۼ�У��͵ı���
    while (count--) {
        sum += *buf++; // ����Ϣ�е�ÿ��WORD�ӵ�sum��
        if (sum & 0xffff0000) { // ���
            sum &= 0xffff; // ������16λ
            sum++; // �ع�
        }
    }
    return ~(sum & 0xffff); // ȡ��sum�ĵ�16λ�����أ��õ����յ�У���
}

// �ӳٺ���
void delayPacket() {
    this_thread::sleep_for(chrono::milliseconds(PACKET_DELAY_MS));//ʹ��ǰ�߳����ߣ���ִͣ�У�һ��ʱ��
}

// �ͻ��������˽������ӣ���ȡ�������ֵķ�ʽ��
// ������socketClient - �ͻ����׽��֣�servAddr - ��������ַ��servAddrlen - ��������ַ���ȣ�label - ��ǩ
int Client_Server_Connect(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, int label) {
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet)]);  // ����ָ�룺���ڴ洢���ͺͽ��յ����ݰ�

    try {
        // ��һ�����֣��ͻ������������˷���SYN��������������
        packet.tag = SYN;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));

        if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
            throw runtime_error("����SYNʧ�ܣ������룺" + to_string(WSAGetLastError()));
        }
        cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
        cout << "\033[32m" << "| �ɹ����͵�һ��������Ϣ |" << "\033[0m" << endl;

        // Jacobson/Karels�㷨��ʼ��RTT��ز���
        double estimatedRTT = 1.0;  // ���Ƶ�RTT����ʼֵ��Ϊ1��
        double devRTT = 0.0;        // RTTƫ��
        const double alpha = 0.125; // ����RTT��Ȩ��
        const double beta = 0.25;   // ƫ��Ȩ��
        double timeoutDuration = estimatedRTT + 4 * devRTT;  // ��ʼ����ʱʱ��

        u_long mode = 1; // ����Ϊ������ģʽ
        ioctlsocket(socketClient, FIONBIO, &mode);

        // �ڶ������֣��ͻ��˽��շ���˻ش������֣�SYN-ACK��
        clock_t start = clock();
        while (recvfrom(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
            if (double(clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
                start = clock();
                cout << "\033[34m" << "��һ�����ֳ�ʱ�����ڽ����ش�" << "\033[0m" << endl;
                timeoutDuration = estimatedRTT + 4 * devRTT;
            }
        }

        double sampleRTT = double(clock() - start) / CLOCKS_PER_SEC;
        estimatedRTT = (1 - alpha) * estimatedRTT + alpha * sampleRTT;
        devRTT = (1 - beta) * devRTT + beta * abs(sampleRTT - estimatedRTT);
        timeoutDuration = estimatedRTT + 4 * devRTT;

        mode = 0; // �ָ�����ģʽ
        ioctlsocket(socketClient, FIONBIO, &mode);

        memcpy(&packet, buffer.get(), sizeof(packet));
        if (!(packet.tag == ACK && compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            throw runtime_error("�޷����շ���˻ش�ACK����У��ʹ���");
        }
        cout << "\033[32m" << "| �ɹ����յڶ���������Ϣ |" << "\033[0m" << endl;

        // ���������֣��ͻ��˷���ACK���������������
        packet.tag = ACK_SYN;
        packet.datasize = label;
        packet.checksum = 0;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
            throw runtime_error("����ACK_SYNʧ�ܣ������룺" + to_string(WSAGetLastError()));
        }

        cout << "\033[32m" << "| �ɹ����͵�����������Ϣ |" << "\033[0m" << endl;
        cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
        cout << "\033[32m" << "�ͻ��������˳ɹ������������ֽ������ӣ����Կ�ʼ����/��������" << "\033[0m" << endl;
    }
    catch (const runtime_error& e) {
        cout << "\033[31m" << "�쳣����: " << e.what() << "\033[0m" << endl;
        return -1;
    }
    return 1;
}

// �ͻ�����������˶Ͽ����ӣ��Ĵλ���)
// ������socketClient - �ͻ����׽��֣�servAddr - ��������ַ��servAddrlen - ��������ַ����
int Client_Server_Disconnect(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen) {
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet)]);

    try {
        // �ͻ��˵�һ�η�����֣�FIN_ACK��
        packet.tag = FIN_ACK;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
            throw runtime_error("����FIN_ACKʧ�ܣ������룺" + to_string(WSAGetLastError()));
        }
        cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
        cout << "\033[32m" << "| �ɹ����͵�һ�λ�����Ϣ |" << "\033[0m" << endl;

        // �ȴ����շ���˷����ĵڶ��λ���
        clock_t start = clock(); // ��ʼ��ʱ
        int retryCount = 0;
        int timeoutDuration = 1; // ��ʼ��ʱʱ��Ϊ1��

        while (true) {
            if (recvfrom(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
                if ((clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                    retryCount++;
                    if (retryCount > MAX_RETRY_COUNT) {
                        throw runtime_error("�ڶ��λ����ش������������ƣ������룺" + to_string(WSAGetLastError()));
                    }
                    cout << "\033[34m" << "�ڶ��λ��ֳ�ʱ�����ڽ��е� " << retryCount << " ���ش�" << "\033[0m" << endl;
                    if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
                        throw runtime_error("�ش�ʧ�ܣ������룺" + to_string(WSAGetLastError()));
                    }
                    start = clock(); // ���ü�ʱ��
                    timeoutDuration *= 2; // ָ���˱�
                }
            }
            else {
                cout << "\033[32m" << "| �ɹ����յڶ��λ�����Ϣ |" << "\033[0m" << endl;
                break;
            }
        }

        // �ȴ��������ĵ����λ���(FIN_ACK)
        start = clock(); // ���ü�ʱ��
        retryCount = 0;
        timeoutDuration = 1; // ���ó�ʱʱ��
        while (true) {
            if (recvfrom(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
                if ((clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                    retryCount++;
                    if (retryCount > MAX_RETRY_COUNT) {
                        throw runtime_error("�����λ����ش������������ƣ������룺" + to_string(WSAGetLastError()));
                    }
                    cout << "\033[34m" << "�ȴ������λ��ֳ�ʱ�����ڽ��е� " << retryCount << " ���ش�" << "\033[0m" << endl;
                    start = clock(); // ���ü�ʱ��
                    timeoutDuration *= 2; // ָ���˱�
                }
            }
            else {
                cout << "\033[32m" << "| �ɹ����յ����λ�����Ϣ |" << "\033[0m" << endl;
                break;
            }
        }

        // �ͻ��˷��͵��Ĵλ�������(ACK)
        packet.tag = ACK;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));

        if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
            throw runtime_error("���͵��Ĵλ�������ʧ�ܣ������룺" + to_string(WSAGetLastError()));
        }

        cout << "\033[32m" << "| �ɹ����͵��Ĵλ�����Ϣ |" << "\033[0m" << endl;
        cout << "\033[32m" << "+------------------------+" << "\033[0m" << endl;
        cout << "\033[32m" << "�ͻ��������˳ɹ��Ͽ����ӣ�" << "\033[0m" << endl;
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
        if (((rand() % (255 - 1)) + 1) == 199 && timeoutTestFlag) {
            cout << endl << "\033[34m[TEST] \033[0m �����ʱ�ش����Դ��� - Seq��" << int(packet.seq) << endl;
            timeoutTestFlag = false;
            continue;
        }

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

                // delayPacket();

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

            if (((rand() % (255 - 1)) + 1) != 187) {
                sendto(socketServer, receiveBuffer, sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen);
                cout << "\033[32m[INFO]\033[0m �ɹ�����ACK��Ӧ - Seq: " << int(packet.seq) << ", Ack: " << int(packet.ack) << endl;
            }
            else {
                cout << "\033[34m[TEST]\033[0m �ۼ�ȷ�ϲ��Դ��� - ���к�: " << int(packet.seq) << ", δ����ACK" << endl;
            }

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

    clock_t startTime = clock(); // ���ڼ���ʱ��������

    // �����������ݰ�
    while (BaseIndex < (totalPacketCount - 1)) {
        /*
        ���ͻ��������������ݰ���1.�ڷ��ͻ�������2.û�г�������

        BaseIndex   NextSeqNum    BaseIndex + Window         totalPacketCount
        +---------------+-----------------+---------- ... ... -----------+
        */
        while (NextSeqNum <= BaseIndex + Window && NextSeqNum < totalPacketCount)
        {
            cout << "\033[33m[INFO]\033[0m ׼���������ݰ� - ��ǰ�������� - BaseIndex: " << BaseIndex << ", NextSeqNum: " << NextSeqNum << endl;
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

            // delayPacket();

            sendto(socketClient, stagingBuffer[NextSeqNum % Window], sizeof(packet) + packetDataSize, 0, (sockaddr*)&servAddr, servAddrlen);

            // ������ʱ��
            if (!timerRunning) {
                timerStart = clock();
                timerRunning = true;
            }

            cout << "\033[32m[INFO]\033[0m �������ݰ� - ���ݴ�С: " << packetDataSize << " �ֽ�, Seq: " << int(packet.seq) << ", CheckSum: " << int(packet.checksum) << ", �׸�δȷ�����ݰ����: " << lastUnacknowledgedPacketIndex << endl;
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
            cout << "\033[33m[INFO]\033[0m ���յ�ACK�����»������� - BaseIndex: " << BaseIndex << ", NextSeqNum: " << NextSeqNum << endl;
        }
        else {
            // ��֤�������к�ѭ���������
            // -  dis > 0������ack���ڵ�ǰack֮�� -> �������
            // - dis <= 0�����кų���ѭ������ǰ ack �� 250�����յ��� ack �� 5��5 Ӧ������ 250 ֮����� -> ���㷽ʽ��Ϊ: (int(packet.ack) + 256 - Ack_num)
            int dis = (int(packet.ack) - Ack_num) > 0 ? (int(packet.ack) - Ack_num) : (int(packet.ack) + 256 - Ack_num);
            
            int duplicateAckCount = 0;

            // ��⵽�ظ�ȷ��
            if (packet.ack == (Ack_num == 0 ? 255 : Ack_num - 1)) {
                // ���Ack_num��0��ǰһ��ȷ�Ϻ�Ӧ����255���������Ack_num - 1��
                cout << "\033[31m[WARNING]\033[0m �յ��ظ�ȷ�ϣ�Ack: " << int(packet.ack) << endl;
                // ����������ʵ�ֿ����ش����ƣ������Ҫ��
                /*
                duplicateAckCount++;
                if (duplicateAckCount >= 3) {
                    // �ش�����δ��ȷ�ϵ����ݰ�
                    int packetIndex = lastUnacknowledgedPacketIndex % Window;
                    sendto(socketClient, stagingBuffer[packetIndex], sizeof(packet) + stagingBufferLengths[packetIndex], 0, (sockaddr*)&servAddr, servAddrlen);
                    cout << "\033[31m[INFO]\033[0m �����ش��������ش����ݰ� Seq: " << lastUnacknowledgedPacketIndex << endl;

                    // �����ظ�ACK����
                    duplicateAckCount = 0;
                }
                */
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
                    cout << "\033[33m[INFO]\033[0m �ۼ�ȷ�ϣ����»������� - BaseIndex: " << BaseIndex << ", NextSeqNum: " << NextSeqNum << endl;
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

    // ����ʱ��������ʼ���
    clock_t endTime = clock();
    double totalDuration = double(endTime - startTime) / CLOCKS_PER_SEC;
    double throughput = mes_size / totalDuration;
    //cout << "\033[32m[INFO]\033[0m �ܷ���ʱ��: " << totalDuration << " ��, ������: " << throughput << " �ֽ�/��" << endl;

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
    SOCKET client = socket(AF_INET, SOCK_DGRAM, 0);
    if (client == INVALID_SOCKET)
    {
        cout << "\033[31m" << "�׽��ִ���ʧ�ܣ������룺" << WSAGetLastError() << "\033[0m" << endl;
        WSACleanup();
        return 1;
    }

    cout << "\033[32m" << "�ͻ����׽��ִ����ɹ�" << "\033[0m" << endl;

    // ���÷�������ַ
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(PORT);
    inet_pton(AF_INET, IP, &serveraddr.sin_addr.s_addr);

    // ѡ�����ģʽ
    cout << "\033[33m" << "��ѡ�����ģʽ������0 / ����1����" << "\033[0m" << endl;
    int label;
    cin >> label;

    // ���ӵ�������
    int length = sizeof(serveraddr);
    cout << "\033[33m" << "�������������������...\n" << "\033[0m";
    if (Client_Server_Connect(client, serveraddr, length, label) == -1)
    {
        cout << "\033[31m" << "���ӽ���ʧ�ܡ�" << "\033[0m" << endl;
        closesocket(client);
        WSACleanup();
        return 1;
    }

    cout << "\033[33m" << "���ݻ�������С��" << DEFAULT_BUFFER_SIZE << " �������ڻ�������С��" << DEFAULT_WINDOW_SIZE << "\033[33m" << endl;

    if (label == 0) // ��������
    {
        while (true)
        {
            cout << "\033[33m" << "======================= ѡ��Ҫ���͵��ļ� =======================" << "\033[0m" << endl;
            char InFileName[20];
            cout << "\033[33m" << "�����ļ��������� 'q' �˳���:" << "\033[0m" << endl;
            cin >> InFileName;

            if (strcmp(InFileName, "q") == 0)
            {
                Packet_Header packet;
                unique_ptr<char[]> buffer(new char[sizeof(packet)]);
                packet.tag = END;
                packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
                memcpy(buffer.get(), &packet, sizeof(packet));
                sendto(client, buffer.get(), sizeof(packet), 0, (sockaddr*)&serveraddr, length);
                cout << "\033[32m" << "����ȫ�ֽ�����־��������" << "\033[0m" << endl;
                break;
            }

            ifstream file_stream(InFileName, ios::binary | ios::ate);
            if (!file_stream)
            {
                cout << "\033[31m" << "�ļ���ʧ��" << "\033[0m" << endl;
                continue;
            }

            int F_length = static_cast<int>(file_stream.tellg());
            file_stream.seekg(0, file_stream.beg);
            unique_ptr<char[]> FileBuffer(new char[F_length]);
            file_stream.read(FileBuffer.get(), F_length);

            cout << "\033[32m" << "�����ļ����ݴ�С��" << F_length << " �ֽ�" << "\033[0m" << endl;

            SendMessage(client, serveraddr, length, InFileName, strlen(InFileName), DEFAULT_BUFFER_SIZE, DEFAULT_WINDOW_SIZE);
            clock_t start = clock();
            SendMessage(client, serveraddr, length, FileBuffer.get(), F_length, DEFAULT_BUFFER_SIZE, DEFAULT_WINDOW_SIZE);
            clock_t end = clock();
            cout << "\033[32m" << "������ʱ����" << (end - start) / CLOCKS_PER_SEC << " �롣" << "\033[0m" << endl;
            cout << "\033[32m" << "�����ʣ�" << static_cast<float>(F_length) / ((end - start) / CLOCKS_PER_SEC) << " �ֽ�/�롣" << "\033[0m" << endl;
            cout << "\033[33m" << "=====================================================================" << "\033[0m" << endl;
        }
    }
    else if (label == 1)
    {
        while (true)
        {
            cout << "\033[33m" << "======================= �ȴ��������� =======================" << "\033[0m" << endl;

            unique_ptr<char[]> F_name(new char[20]);
            unique_ptr<char[]> Message(new char[100000000]);
            int name_len = RecvMessage(client, serveraddr, length, F_name.get(), DEFAULT_BUFFER_SIZE, DEFAULT_WINDOW_SIZE);

            if (name_len == 999)
            {
                cout << "\033[32m" << "���յ�ȫ�ֽ�����־���˳�����ѭ��" << "\033[0m" << endl;
                break;
            }

            int file_len = RecvMessage(client, serveraddr, length, Message.get(), DEFAULT_BUFFER_SIZE, DEFAULT_WINDOW_SIZE);
            string fileName(F_name.get(), name_len);
            cout << "\033[32m" << "���յ��ļ�����" << fileName << "\033[0m" << endl;
            cout << "\033[32m" << "���յ��ļ����ݴ�С��" << file_len << " �ֽ�" << "\033[0m" << endl;

            ofstream file_stream(fileName, ofstream::binary);
            if (!file_stream) {
                cout << "\033[31m" << "�ļ���ʧ�ܣ�" << "\033[0m" << endl;
                continue;
            }
            file_stream.write(Message.get(), file_len);
            file_stream.close();

            cout << "\033[32m" << "======================= ���ݽ�����ϣ��ļ��ѱ��� =======================" << "\033[0m" << endl;
        }
    }

    Client_Server_Disconnect(client, serveraddr, length);
    this_thread::sleep_for(chrono::milliseconds(500));
    closesocket(client);
    WSACleanup();
    cout << "\033[33m" << "======================= ������� =======================" << "\033[0m" << endl;
    system("pause");
    return 0;
}
