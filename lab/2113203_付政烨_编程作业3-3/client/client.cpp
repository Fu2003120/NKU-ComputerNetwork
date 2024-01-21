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

const BYTE SYN = 0x1;		//��ʼ����������SYN = 1 ACK = 0 FIN = 0
const BYTE ACK = 0x2;		//ȷ���յ���Ϣ��SYN = 0 ACK = 1 FIN = 0
const BYTE ACK_SYN = 0x3;	//ȷ����������SYN = 1 ACK = 1 FIN = 0
const BYTE FIN = 0x4;		//��ʼ��ֹ���ӣ�FIN = 1 ACK = 0 SYN = 0
const BYTE FIN_ACK = 0x6;	//ȷ��������ֹ��FIN = 1 ACK = 1 SYN = 0
const BYTE OVER = 0x8;		//���ݴ������
const BYTE END = 0x16;		//ͨ�Ź���ȫ�ֽ���

// ������������ĳ�ʼ��
random_device rd;
mt19937 gen(rd());
uniform_int_distribution<> dis(0, 99);

bool shouldDropPacket() {
    return dis(gen) < (LOSS_RATE * 100);
}

typedef struct Packet_Header
{
    WORD datasize;		// ���ݳ���
    BYTE tag;			// ��ǩ����λ��ʹ�ú���λ��������OVER FIN ACK SYN 
    BYTE WindowSize;	// ���ڴ�С
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

// �ӳٺ���
void delayPacket() {
    this_thread::sleep_for(chrono::milliseconds(PACKET_DELAY_MS));//ʹ��ǰ�߳����ߣ���ִͣ�У�һ��ʱ��
}

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

// �ͻ��������˽������ӣ���ȡ�������ֵķ�ʽ��
// ������socketClient - �ͻ����׽��֣�servAddr - ��������ַ��servAddrlen - ��������ַ���ȣ�label - ��ǩ
int Client_Server_Connect(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, int label) {
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet)]);  // ����ָ�룺���ڴ洢���ͺͽ��յķ���

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

// SR���Ͷ˺���
void SendMessage(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, char* Message, int mes_size, int MAX_SIZE, int WindowSize) {
    Packet_Header packet;
    int totalPacketNum = mes_size / MAX_SIZE + (mes_size % MAX_SIZE != 0);
    int base = 0;           // ���ڻ����
    int nextSeqNum = 0;     // �������к�

    // ��ʼ�����ͻ�����
    char** stagingBuffer = new(nothrow) char* [WindowSize];
    int* stagingBufferLengths = new(nothrow) int[WindowSize];
    for (int i = 0; i < WindowSize; i++) {
        stagingBuffer[i] = new(nothrow) char[sizeof(packet) + MAX_SIZE];
    }

    // ��ʼ������ȷ��״̬�Ͷ�ʱ��
    bool* ackReceived = new(nothrow) bool[WindowSize];
    clock_t* packetTimers = new(nothrow) clock_t[WindowSize];
    bool* timerRunning = new(nothrow) bool[WindowSize];
    for (int i = 0; i < WindowSize; i++) {
        ackReceived[i] = false;
        timerRunning[i] = false;
    }

    // ����Ϊ������ģʽ
    u_long socketMode = 1;
    ioctlsocket(socketClient, FIONBIO, &socketMode);

    // ���ͷ���
    while (base <  totalPacketNum) {
        // ���ʹ����ڵķ���
        while (nextSeqNum < base + WindowSize && nextSeqNum < totalPacketNum) {
            // ��������С
            int packetDataSize = (nextSeqNum == totalPacketNum - 1) ? mes_size - (totalPacketNum - 1) * MAX_SIZE : MAX_SIZE;
            
            // ���÷���ͷ����Ϣ
            packet.tag = 0;
            packet.seq = nextSeqNum % 256;
            packet.seq_quotient = nextSeqNum / 256;                 // ���ڽ��ն˻ָ�ʵ�ʵ����к�
            packet.datasize = packetDataSize;
            packet.WindowSize = WindowSize - (nextSeqNum - base);   // ��ǰ�����л����Է��͵ķ�������
            packet.checksum = 0;
            packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));

            // ���Ʒ��鵽���ͻ�����
            memcpy(stagingBuffer[nextSeqNum % WindowSize], &packet, sizeof(packet));
            char* messageFragment = Message + nextSeqNum * MAX_SIZE;
            memcpy(stagingBuffer[nextSeqNum % WindowSize] + sizeof(packet), messageFragment, packetDataSize);
            stagingBufferLengths[nextSeqNum % WindowSize] = packetDataSize;


            // �ж��Ƿ�Ӧ�ö���
            if (shouldDropPacket()) {
                cout << "\033[31m+-------------------------------------------------------------+" << endl;
                cout << "|[WARNING] ���鶪������ - ��ʧ: " << nextSeqNum << "�� ���ݰ� " << endl;
                cout << "+-------------------------------------------------------------+\033[0m" << endl;
            }
            else {
                sendto(socketClient, stagingBuffer[nextSeqNum % WindowSize], sizeof(packet) + packetDataSize, 0, (sockaddr*)&servAddr, servAddrlen);
                cout << "\033[33m[SEND]\033[0m ���ͷ��� - ���к�: " << nextSeqNum << "��packet���к�: " << int(packet.seq) << ", У���: " << int(packet.checksum) << "" << endl;
            }
            
            
            // ���������ö�ʱ��,�������ÿ�����͵ķ�������ظ����䳬ʱ״̬
            packetTimers[nextSeqNum % WindowSize] = clock();
            timerRunning[nextSeqNum % WindowSize] = true;

            nextSeqNum++;
        }

        char receiveBuffer[sizeof(packet)];

        // �ش�����
        while (recvfrom(socketClient, receiveBuffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
            // ���������ѷ��͵���δ�յ�ACKȷ�ϵķ���
            for (int i = base; i < nextSeqNum; i++) {
                if (!ackReceived[i % WindowSize] && (clock() - packetTimers[i % WindowSize]) / CLOCKS_PER_SEC > RESEND_TNTERVAL) {
                    sendto(socketClient, stagingBuffer[i % WindowSize], sizeof(packet) + stagingBufferLengths[i % WindowSize], 0, (sockaddr*)&servAddr, servAddrlen);
                    cout << "\033[31m[WARNING]\033[0m û�н��յ�ack��������ʱ - �ش����飬δȷ�ϰ���ţ�" << i << endl;
                    packetTimers[i % WindowSize] = clock();  
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
        int packetIndex = int(packet.ack) % WindowSize;

        // ����Ƿ��ظ�����
        if (!ackReceived[packetIndex]) {
            // ���½��ձ�ǺͶ�ʱ��
            ackReceived[packetIndex] = true;
            timerRunning[packetIndex] = false;
            cout << "\033[32m[ACC]\033[0m �յ�ȷ�� - ACK: " << int(packet.ack) << "����Ӧ��������: " << packetIndex << endl;

            // ��������
            while (ackReceived[base % WindowSize] && base < nextSeqNum) {
                // ���ô��ڻ�������λ�õ�ackReceived״̬
                ackReceived[base % WindowSize] = false;
                timerRunning[base % WindowSize] = false;
                base++;
                cout << "\033[35m[MOVING]\033[0m �յ�˳������ȷ�Ϻ� - ���ڻ��� - �� " << base << " �� " << base + WindowSize << endl;
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
    for (int i = 0; i < WindowSize; i++) {
        delete[] stagingBuffer[i];
    }
    delete[] stagingBuffer;
    delete[] stagingBufferLengths;

}

// SR���ն˺���
int RecvMessage(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen, char* Message, int MAX_SIZE, int WindowSize) {
    Packet_Header packet;
    char* receiveBuffer = new (nothrow) char[sizeof(packet) + MAX_SIZE];
    int rcv_base = 0;               // ���ڻ����
    long totalDataLength = 0;       // �ѽ��յ������ܳ���

    // ��ʼ�����ն˻������ͱ������
    char** packetBuffer = new char* [2 * WindowSize];  // �޸�Ϊ2N��С�Ļ�����
    bool* isReceived = new bool[2 * WindowSize];
    for (int i = 0; i < 2 * WindowSize; ++i) {
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
            int bufferIndex = seqNum % (2 * WindowSize);  // ������Ӧ2N��С�Ļ�����
            Packet_Header ackPacket;

            // ������к��Ƿ���2�����ڷ�Χ��
            bool isInDoubleWindowSize = (seqNum >= rcv_base - WindowSize) && (seqNum < rcv_base + WindowSize);

            if (isInDoubleWindowSize) {
                // ����ACK����ʹ���ݰ����ڵ�ǰ���մ�����
                ackPacket.tag = 0;
                ackPacket.ack = seqNum;
                ackPacket.checksum = 0;
                ackPacket.checksum = compute_sum((WORD*)&ackPacket, sizeof(ackPacket));
                memcpy(receiveBuffer, &ackPacket, sizeof(ackPacket));
                sendto(socketServer, receiveBuffer, sizeof(ackPacket), 0, (sockaddr*)&clieAddr, clieAddrlen);
                cout << "\033[33m[SEND]\033[0m ����ȷ����Ϣ - ȷ�Ϻ�: " << int(ackPacket.ack) << ", У���: " << int(packet.checksum) << endl;
            }

            // ������к��ڵ�ǰ���մ�����
            if ((seqNum >= rcv_base) && (seqNum < rcv_base + WindowSize)) {
                // �����ǰû���յ��������кŵ����ݰ����򻺴�����
                if (!isReceived[bufferIndex]) {
                    // �������ݵ�������
                    memcpy(packetBuffer[bufferIndex], receiveBuffer + sizeof(packet), packet.datasize);
                    isReceived[bufferIndex] = true;
                    cout << "\033[36m[INFO]\033[0m ���ݰ��ɹ����ղ����� - ���к�: " << seqNum << endl;

                    // ����Ǵ�����߽磬���Խ�������
                    if (seqNum == rcv_base) {
                        while (isReceived[rcv_base % (2 * WindowSize)]) {
                            memcpy(Message + totalDataLength, packetBuffer[rcv_base % (2 * WindowSize)], packet.datasize);
                            totalDataLength += packet.datasize;
                            isReceived[rcv_base % (2 * WindowSize)] = false;
                            rcv_base++;
                            cout << "\033[35m[MOVING]\033[0m �յ�˳������ȷ�Ϻ� - ���ڻ��� - �� " << rcv_base << " �� " << rcv_base + WindowSize << endl;
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
    for (int i = 0; i < 2 * WindowSize; ++i) {
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
