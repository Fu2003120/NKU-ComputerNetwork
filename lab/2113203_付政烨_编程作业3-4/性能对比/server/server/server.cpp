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
const BYTE OVER = 0x8;		//������־
const BYTE END = 0x16;		//ȫ�ֽ�����־

// ������������ĳ�ʼ��
random_device rd;
mt19937 gen(rd());
uniform_int_distribution<> dis(0, 99);

bool shouldDropPacket() {
    return dis(gen) < (LOSS_RATE * 100);
}

struct Packet_Header
{
    WORD datasize;		// ���ݳ���
    BYTE tag;			// ��ǩ
    //��λ��ʹ�ú���λ��������OVER FIN ACK SYN 
    BYTE WindowSize;		// ���ڴ�С
    BYTE seq;			// ���к�
    BYTE seq_quotient;	// ���кţ��̣�
    BYTE ack;			// ȷ�Ϻ�
    WORD checksum;		// У���

    // ��ʼ��
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

// ����У��͵ĺ���
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

// ���Ͷ�
void SendMessage(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, char* Message, int mes_size, int MAX_SIZE, int WindowSizeSize) {
    Packet_Header packet;
    int totalPacketNum = mes_size / MAX_SIZE + (mes_size % MAX_SIZE != 0);
    int base = 0;           // ���ڻ����
    int nextSeqNum = 0;     // �������к�

    // ��ʼ�����ͻ�����
    char** stagingBuffer = new(nothrow) char* [WindowSizeSize];
    int* stagingBufferLengths = new(nothrow) int[WindowSizeSize];
    for (int i = 0; i < WindowSizeSize; i++) {
        stagingBuffer[i] = new(nothrow) char[sizeof(packet) + MAX_SIZE];
    }

    // ��ʼ������ȷ��״̬�Ͷ�ʱ��
    bool* ackReceived = new(nothrow) bool[WindowSizeSize];
    clock_t* packetTimers = new(nothrow) clock_t[WindowSizeSize];
    bool* timerRunning = new(nothrow) bool[WindowSizeSize];
    for (int i = 0; i < WindowSizeSize; i++) {
        ackReceived[i] = false;
        timerRunning[i] = false;
    }

    // ����Ϊ������ģʽ
    u_long socketMode = 1;
    ioctlsocket(socketClient, FIONBIO, &socketMode);

    // ���ͷ���
    while (base < totalPacketNum) {
        // ���ʹ����ڵķ���
        while (nextSeqNum < base + WindowSizeSize && nextSeqNum < totalPacketNum) {
            // ��������С
            int packetDataSize = (nextSeqNum == totalPacketNum - 1) ? mes_size - (totalPacketNum - 1) * MAX_SIZE : MAX_SIZE;

            // ���÷���ͷ����Ϣ
            packet.tag = 0;
            packet.seq = nextSeqNum % 256;
            packet.seq_quotient = nextSeqNum / 256;                 // ���ڽ��ն˻ָ�ʵ�ʵ����к�
            packet.datasize = packetDataSize;
            packet.WindowSize = WindowSizeSize - (nextSeqNum - base);   // ��ǰ�����л����Է��͵ķ�������
            packet.checksum = 0;
            packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));

            // ���Ʒ��鵽���ͻ�����
            memcpy(stagingBuffer[nextSeqNum % WindowSizeSize], &packet, sizeof(packet));
            char* messageFragment = Message + nextSeqNum * MAX_SIZE;
            memcpy(stagingBuffer[nextSeqNum % WindowSizeSize] + sizeof(packet), messageFragment, packetDataSize);
            stagingBufferLengths[nextSeqNum % WindowSizeSize] = packetDataSize;
            sendto(socketClient, stagingBuffer[nextSeqNum % WindowSizeSize], sizeof(packet) + packetDataSize, 0, (sockaddr*)&servAddr, servAddrlen);
            cout << "\033[33m[SEND]\033[0m ���ͷ��� - ���к�: " << nextSeqNum << "��packet���к�: " << int(packet.seq) << ", У���: " << int(packet.checksum) << "" << endl;

            // ���������ö�ʱ��,�������ÿ�����͵ķ�������ظ����䳬ʱ״̬
            packetTimers[nextSeqNum % WindowSizeSize] = clock();
            timerRunning[nextSeqNum % WindowSizeSize] = true;

            nextSeqNum++;
        }

        char receiveBuffer[sizeof(packet)];

        // �ش�����
        while (recvfrom(socketClient, receiveBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
            // ���������ѷ��͵���δ�յ�ACKȷ�ϵķ���
            for (int i = base; i < nextSeqNum; i++) {
                if (!ackReceived[i % WindowSizeSize] && (clock() - packetTimers[i % WindowSizeSize]) / CLOCKS_PER_SEC > RESEND_TNTERVAL) {
                    sendto(socketClient, stagingBuffer[i % WindowSizeSize], sizeof(packet) + stagingBufferLengths[i % WindowSizeSize], 0, (sockaddr*)&servAddr, servAddrlen);
                    cout << "\033[31m[WARNING]\033[0m û�н��յ�ack��������ʱ - �ش����飬δȷ�ϰ���ţ�" << i << endl;
                    packetTimers[i % WindowSizeSize] = clock();
                }
            }
        }

        // ������յ���ȷ����Ϣ
        memcpy(&packet, receiveBuffer, sizeof(packet));

        // У�����
        if ((compute_sum((WORD*)&packet, sizeof(packet)) != 0)) {
            cout << "\033[31m[ERROR]\033[0m ���յ���ACK��У��ʧ�ܣ�У��ͣ�" << int(packet.checksum) << endl;
            continue;
        }

        // �ɹ��յ�ACK
        int packetIndex = int(packet.ack) % WindowSizeSize;

        // ����Ƿ��ظ�����
        if (!ackReceived[packetIndex]) {
            // ���½��ձ�ǺͶ�ʱ��
            ackReceived[packetIndex] = true;
            timerRunning[packetIndex] = false;
            cout << "\033[32m[ACC]\033[0m �յ�ȷ�� - ACK: " << int(packet.ack) << "����Ӧ��������: " << packetIndex << endl;

            // ��������
            while (ackReceived[base % WindowSizeSize] && base < nextSeqNum) {
                // ���ô��ڻ�������λ�õ�ackReceived״̬
                ackReceived[base % WindowSizeSize] = false;
                timerRunning[base % WindowSizeSize] = false;
                base++;
                cout << "\033[35m[MOVING]\033[0m �յ�˳������ȷ�Ϻ� - ���ڻ��� - �� " << base << " �� " << base + WindowSizeSize << endl;
            }
        }
        else {
            cout << "\033[33m[WARNING]\033[0m �յ��ظ�ȷ�� ACK: " << int(packet.ack) << endl;
        }
    }

    // ���ͽ�����־
    packet.tag = OVER;
    char* endSignalBuffer = new char[sizeof(packet)];
    packet.checksum = 0;
    packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
    memcpy(endSignalBuffer, &packet, sizeof(packet));
    sendto(socketClient, endSignalBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
    cout << "\033[33m[SEND]\033[0m ������־�ѷ���" << endl;

    // ȷ�Ͻ�����־�Ľ���
    clock_t endSignalStartTime = clock();
    while (recvfrom(socketClient, endSignalBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
        if ((clock() - endSignalStartTime) / CLOCKS_PER_SEC > RESEND_TNTERVAL) {
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
        cout << "\033[32m[ACC]\033[0m �ɹ����յ�������־" << endl;
    }
    else {
        cout << "\033[31m[WARNING]\033[0m  �޷����տͻ��˻ش��Ľ�����־" << endl;
    }

    // ������Դ
    delete[] ackReceived;
    delete[] packetTimers;
    delete[] timerRunning;
    for (int i = 0; i < WindowSizeSize; i++) {
        delete[] stagingBuffer[i];
    }
    delete[] stagingBuffer;
    delete[] stagingBufferLengths;

}

// ���ն�
int RecvMessage(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen, char* Message, int MAX_SIZE, int WindowSizeSize) {
    Packet_Header packet;
    char* receiveBuffer = new (nothrow) char[sizeof(packet) + MAX_SIZE];
    int rcv_base = 0;               // ���ڻ����
    long totalDataLength = 0;       // �ѽ��յ������ܳ���

    // ��ʼ�����ն˻������ͱ������
    char** packetBuffer = new char* [2 * WindowSizeSize];  // �޸�Ϊ2N��С�Ļ�����
    bool* isReceived = new bool[2 * WindowSizeSize];
    for (int i = 0; i < 2 * WindowSizeSize; ++i) {
        packetBuffer[i] = new char[sizeof(packet) + MAX_SIZE];
        isReceived[i] = false;
    }

    while (true) {
        while (recvfrom(socketServer, receiveBuffer, sizeof(packet) + MAX_SIZE, 0, (sockaddr*)&clieAddr, &clieAddrlen) <= 0);

        memcpy(&packet, receiveBuffer, sizeof(packet));

        // ����ȫ�ֽ������
        if (packet.tag == END && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            cout << "\033[32m[ACC]\033[0m ȫ�ֽ�����־�ѽ���" << endl;
            return 999;
        }

        // ���������ݰ����ͽ������
        if (packet.tag == OVER && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            cout << "\033[32m[ACC]\033[0m ������־�ѽ���" << endl;
            break;
        }

        // У�����ݰ�
        if (packet.tag == 0 && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            int seqNum = int(packet.seq) + int(packet.seq_quotient) * 256;
            int bufferIndex = seqNum % (2 * WindowSizeSize);  // ������Ӧ2N��С�Ļ�����
            Packet_Header ackPacket;
            // ������к��Ƿ���2�����ڷ�Χ��
            bool isInDoubleWindowSizeSize = (seqNum >= rcv_base - WindowSizeSize) && (seqNum < rcv_base + WindowSizeSize);

            if (isInDoubleWindowSizeSize) {
                // ����ACK����ʹ���ݰ����ڵ�ǰ���մ�����

                ackPacket.tag = 0;
                ackPacket.ack = seqNum;
                ackPacket.checksum = 0;
                ackPacket.checksum = compute_sum((WORD*)&ackPacket, sizeof(ackPacket));
                memcpy(receiveBuffer, &ackPacket, sizeof(ackPacket));

                // �ж��Ƿ�Ӧ�ö���
                if (shouldDropPacket()) {
                    cout << "\033[31m+-------------------------------------------------------------+" << endl;
                    cout << "|[WARNING] ACK�������� - ��ʧ: " << seqNum << "�� ���ݰ���ȷ�ϻظ� " << endl;
                    cout << "+-------------------------------------------------------------+\033[0m" << endl;
                }
                else {
                    sendto(socketServer, receiveBuffer, sizeof(ackPacket), 0, (sockaddr*)&clieAddr, clieAddrlen);
                    cout << "\033[33m[SEND]\033[0m ����ȷ����Ϣ - ȷ�Ϻ�: " << int(ackPacket.ack) << ", У���: " << int(packet.checksum) << endl;
                }
            }

            // ������к��ڵ�ǰ���մ�����
            if ((seqNum >= rcv_base) && (seqNum < rcv_base + WindowSizeSize)) {
                // �����ǰû���յ��������кŵ����ݰ����򻺴�����
                if (!isReceived[bufferIndex]) {
                    // �������ݵ�������
                    memcpy(packetBuffer[bufferIndex], receiveBuffer + sizeof(packet), packet.datasize);
                    isReceived[bufferIndex] = true;
                    cout << "\033[36m[INFO]\033[0m ���ݰ��ɹ����ղ����� - ���к�: " << seqNum << endl;

                    // ����Ǵ�����߽磬���Խ�������
                    if (seqNum == rcv_base) {
                        while (isReceived[rcv_base % (2 * WindowSizeSize)]) {
                            memcpy(Message + totalDataLength, packetBuffer[rcv_base % (2 * WindowSizeSize)], packet.datasize);
                            totalDataLength += packet.datasize;
                            isReceived[rcv_base % (2 * WindowSizeSize)] = false;
                            rcv_base++;
                            cout << "\033[35m[MOVING]\033[0m �յ�˳������ȷ�Ϻ� - ���ڻ��� - �� " << rcv_base << " �� " << rcv_base + WindowSizeSize << endl;
                        }
                    }
                }
                else {
                    cout << "\033[31m[WARNING]\033[0m �ظ����ݰ� - ���к�: " << seqNum << endl;
                    // ��ʹ���ظ������ݰ�Ҳ����ACK
                    sendto(socketServer, receiveBuffer, sizeof(ackPacket), 0, (sockaddr*)&clieAddr, clieAddrlen);
                    cout << "\033[33m[SEND]\033[0m �ظ����ݰ���ȷ����Ϣ�ѷ��� - ȷ�Ϻ�: " << int(ackPacket.ack) << endl;
                }
            }
        }
    }
    // ���ͽ�����־
    packet.tag = OVER;
    packet.checksum = 0;
    packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
    memcpy(receiveBuffer, &packet, sizeof(packet));
    sendto(socketServer, receiveBuffer, sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen);
    cout << "\033[33m[SEND]\033[0m ������־�ѷ��ͣ�" << endl;

    // ������Դ
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

    cout << "\033[33m" << "���ݻ�������С��" << DEFAULT_BUFFER_SIZE << " �������ڻ�������С��" << DEFAULT_WindowSize_SIZE << "\033[33m" << endl;

    if (label == 0) { // ��������
        while (true) {
            cout << "\033[33m" << "======================= �ȴ��������� =======================" << "\033[0m" << endl;

            unique_ptr<char[]> F_name(new char[20]);
            unique_ptr<char[]> Message(new char[100000000]);
            int name_len = RecvMessage(server, addr, length, F_name.get(), DEFAULT_BUFFER_SIZE, DEFAULT_WindowSize_SIZE);

            if (name_len == 999) { // ����Ƿ���ȫ�ֽ�����־
                cout << "\033[32m" << "���յ�ȫ�ֽ�����־���˳�����ѭ��" << "\033[0m" << endl;
                break;
            }

            int file_len = RecvMessage(server, addr, length, Message.get(), DEFAULT_BUFFER_SIZE, DEFAULT_WindowSize_SIZE); // �����ļ�����
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

            SendMessage(server, addr, length, InFileName, strlen(InFileName), DEFAULT_BUFFER_SIZE, DEFAULT_WindowSize_SIZE); // �����ļ���
            clock_t start = clock(); // ��¼��ʼʱ��
            SendMessage(server, addr, length, FileBuffer.get(), F_length, DEFAULT_BUFFER_SIZE, DEFAULT_WindowSize_SIZE); // �����ļ�����
            clock_t end = clock(); // ��¼����ʱ��
            cout << "\033[33m" << "��������ʱ��" << static_cast<double>(end - start) << "\033[0m" << endl;
            cout << "\033[33m" << "�����ʣ�" << static_cast<double>(F_length) / ((end - start)) << "\033[0m" << endl;
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