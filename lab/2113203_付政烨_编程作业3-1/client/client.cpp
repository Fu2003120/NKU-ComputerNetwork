/*���ܰ������������ӡ�����⡢ȷ���ش��ȡ��������Ʋ���ͣ�Ȼ���*/

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
const int MAX_RETRY_COUNT = 10;  // ����ش�����
const int TEST_TIME = 3;    //ָ���˱ܲ��Դ���
const BYTE SYN = 0x1;		//��ʼ����������SYN = 1 ACK = 0 FIN = 0
const BYTE ACK = 0x2;		//ȷ���յ���Ϣ��SYN = 0 ACK = 1 FIN = 0
const BYTE ACK_SYN = 0x3;	//ȷ����������SYN = 1 ACK = 1 FIN = 0
const BYTE FIN = 0x4;		//��ʼ��ֹ���ӣ�FIN = 1 ACK = 0 SYN = 0
const BYTE FIN_ACK = 0x6;	//ȷ��������ֹ��FIN = 1 ACK = 1 SYN = 0
const BYTE OVER = 0x8;		//���ݴ������
const BYTE END = 0x16;		//ͨ�Ź���ȫ�ֽ���
double PACKET_LOSS_RATE = 0.01; // ������
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

// ��������
bool shouldDropPacket() {
    random_device rd;
    mt19937 gen(rd());//��ʼ�������������
    uniform_real_distribution<> dis(0, 1); //����һ���� [0, 1] ��Χ�ھ��ȷֲ���ʵ���ֲ�
    return dis(gen) < PACKET_LOSS_RATE;//�����������Ƿ�С���趨�Ķ�����
}

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

// �ͻ��������˽������ӣ��������֣�
// ������socketClient - �ͻ����׽��֣�servAddr - ��������ַ��servAddrlen - ��������ַ���ȣ�label - �������ֲ�ͬ�Ŀͻ���
int Client_Server_Connect(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, int label)
{
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet)]);  // ����ָ�룺���ڴ洢���ͺͽ��յ����ݰ�

    try {
        // ��һ�Σ��ͻ������������˷���SYN��������������
        packet.tag = SYN;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));// �����ݰ����Ƶ�������

        // ģ�������ӳ�
        delayPacket();

        // ����SYN����������
        if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
            throw runtime_error("����SYNʧ�ܣ������룺" + to_string(WSAGetLastError()));
        }
        cout << "�ɹ����͵�һ��������Ϣ" << endl;

        // Jacobson/Karels�㷨
        // ��ʼ��RTT��ز���
        double estimatedRTT = 1.0;  // ���Ƶ�RTT����ʼֵ��Ϊ1��
        double devRTT = 0.0;        // RTTƫ��
        const double alpha = 0.125; // ����RTT��Ȩ��
        const double beta = 0.25;   // ƫ��Ȩ��
        double timeoutDuration = estimatedRTT + 4 * devRTT;  // ��ʼ����ʱʱ��
        cout << "��ʼ�ĳ�ʱʱ��: " << timeoutDuration << " ��" << endl;

        // ����Ϊ������ģʽ�����û���յ���Ϣ������ͣ���ڶ�ȡ�������ô���ֱ�����ݵ��ﲢ����ȡ��
        u_long mode = 1;
        ioctlsocket(socketClient, FIONBIO, &mode);

        // �ڶ��Σ��ͻ��˽��շ���˻ش������֣�SYN-ACK��
        clock_t start = clock();// ��ʼ��ʱ
        while (recvfrom(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
            // ����ȴ�������ʱʱ�䣬�����·���SYN�������ü�ʱ��
            if (double(clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
                start = clock();
                cout << "��һ�����ֳ�ʱ�����ڽ����ش�" << endl;
                timeoutDuration = estimatedRTT + 4 * devRTT;  // ���³�ʱʱ��
            }
        }

        // ����RTT����
        double sampleRTT = double(clock() - start) / CLOCKS_PER_SEC;
        estimatedRTT = (1 - alpha) * estimatedRTT + alpha * sampleRTT;
        devRTT = (1 - beta) * devRTT + beta * abs(sampleRTT - estimatedRTT);
        timeoutDuration = estimatedRTT + 4 * devRTT;  // ���³�ʱʱ��

        cout << "����RTT: " << sampleRTT << " ��" << endl;
        cout << "����RTT: " << estimatedRTT << " ��" << endl;
        cout << "RTTƫ��: " << devRTT << " ��" << endl;
        cout << "���º�ĳ�ʱʱ��: " << timeoutDuration << " ��" << endl;

        // �ָ�����ģʽ
        mode = 0;
        ioctlsocket(socketClient, FIONBIO, &mode);

        // �����յ���SYN-ACK���Ƿ���ȷ
        memcpy(&packet, buffer.get(), sizeof(packet));
        if (!(packet.tag == ACK && compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            throw runtime_error("�޷����շ���˻ش�ACK����У��ʹ���");
        }
        cout << "�ɹ��յ��ڶ���������Ϣ" << endl;

        // ���������ͻ��˷���ACK���������������
        packet.tag = ACK_SYN;
        packet.datasize = label;
        packet.checksum = 0;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
            throw runtime_error("����ACK_SYNʧ�ܣ������룺" + to_string(WSAGetLastError()));
        }

        cout << "�ɹ����͵�����������Ϣ" << endl;
        cout << "�ͻ��������˳ɹ������������ֽ������ӣ����Կ�ʼ����/��������" << endl;
    }
    catch (const runtime_error& e) {
        cout << "�쳣����: " << e.what() << endl;
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
        cout << "�ͻ��˷��͵�һ�λ�����Ϣ(FIN_ACK)�ɹ�" << endl;

        // �ȴ����շ���˷����ĵڶ��λ���
        clock_t start = clock(); // ��ʼ��ʱ
        int retryCount = 0;
        int timeoutDuration = 1; // ��ʼ��ʱʱ��Ϊ1��

        // ��������ģʽ��while(true)ѭ��������ʵ�ֳ�ʱ�ش�
        while (true) {
            // ����ʧ��
            if (recvfrom(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
                // ��ʱ�ش�
                if ((clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                    retryCount++;
                    if (retryCount > MAX_RETRY_COUNT) { // ����������ش�����������
                        throw runtime_error("�ڶ��λ����ش������������ƣ������룺" + to_string(WSAGetLastError()));
                    }
                    if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
                        throw runtime_error("�ش�ʧ�ܣ������룺" + to_string(WSAGetLastError()));
                    }                    
                    cout << "�ڶ��λ��ֳ�ʱ�����ڽ��е� " << retryCount << " ���ش�" << endl;
                    start = clock(); // ���ü�ʱ��
                    timeoutDuration *= 2; // ָ���˱ܣ���ʱʱ��ӱ�
                }
                // else:�������ڵȴ���Ӧ���һ�δ�ﵽ��ʱʱ��
            }
            else {
                cout << "�ͻ��˳ɹ����յڶ��λ�����Ϣ(ACK)" << endl;
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
                    if (sendto(socketClient, buffer.get(), sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen) == -1) {
                        throw runtime_error("�ش�ʧ�ܣ������룺" + to_string(WSAGetLastError()));
                    }
                    cout << "�ȴ������λ��ֳ�ʱ�����ڽ��е� " << retryCount << " ���ش�" << endl;
                    start = clock(); // ���ü�ʱ��
                    timeoutDuration *= 2; // ָ���˱�
                }
            }
            else {
                cout << "�ͻ��˳ɹ����յ����λ�����Ϣ(FIN_ACK)" << endl;
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

        cout << "�ͻ��˷��͵��Ĵλ�����Ϣ(ACK)�ɹ�" << endl;
        cout << "�ͻ��������˳ɹ��Ͽ����ӣ�" << endl;
    }
    catch (const runtime_error& e) {
        cout << "�Ͽ����ӹ����з����쳣: " << e.what() << endl;
        return -1;
    }

    return 1; 
}

// ��������
// socketClient - �ͻ��˵��׽��֣�servAddr - �������ĵ�ַ��Ϣ��servAddrlen - ��������ַ��Ϣ�ĳ��ȣ�
// Message - Ҫ���͵���Ϣ��ָ�룬mes_size - ��Ϣ�Ĵ�С��MAX_SIZE - ÿ�����ݰ�������С
void SendMessage(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, char* Message, int mes_size, int MAX_SIZE)
{
    int packet_num = mes_size / (MAX_SIZE)+(mes_size % MAX_SIZE != 0);// ������Ҫ�����ݰ�����
    int Seq_num = 0;  //��ʼ�����к�
    int TestFlag = 0; //ָ���˱��㷨�Ķ�������
    Packet_Header packet;
    u_long mode = 1;
    ioctlsocket(socketClient, FIONBIO, &mode);  // ������ģʽ

    try
    {
        // ѭ�������������ݰ�
        for (int i = 0; i < packet_num; i++)
        {
            // ���㵱ǰ�������ݳ���
            int data_len = (i == packet_num - 1 ? mes_size - (packet_num - 1) * MAX_SIZE : MAX_SIZE);
            // ���ͻ�����
            char* buffer = new char[sizeof(packet) + data_len]; 
            packet.tag = 0;
            packet.seq = Seq_num;
            packet.datasize = data_len;
            packet.checksum = 0;
            packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
            // �����ݰ�ͷ�����Ƶ�������
            memcpy(buffer, &packet, sizeof(packet));
            // ���㵱ǰ���ݰ�����ʼλ��
            char* mes = Message + i * MAX_SIZE;
            // �����ݸ��Ƶ�������
            memcpy(buffer + sizeof(packet), mes, data_len);

            // ģ����ʱ
            delayPacket();

            // ģ�ⶪ��
            bool packetDropped = shouldDropPacket();
            if (packetDropped) {
                cout << "ģ�ⶪ��һ�����ݰ�" << endl;
                // �����ﲻ�������ݣ�����Ȼ�������ȷ�ϵ��߼�
            }
            else {
                // ��������
                sendto(socketClient, buffer, sizeof(packet) + data_len, 0, (sockaddr*)&servAddr, servAddrlen);
                cout << "��ʼ������Ϣ...... ���ݴ�С��" << data_len << " �ֽڣ�" << " Tag��" << int(packet.tag) << " Seq��" << int(packet.seq) << " CheckSum��" << int(packet.checksum) << endl;
            }

            int retryCount = 0;       // �ش�������
            int timeoutDuration = 1;  // ��ʼ��ʱʱ��Ϊ1��
            clock_t start = clock();  // ��¼��ʼ����ʱ��
            clock_t lastSendTime = start;  // ��¼��һ�η���ʱ��

            // �ȴ�����ȷ����Ӧ
            while (recvfrom(socketClient, buffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
                // ��ʱ�ش��߼�����������˳�ʱʱ�䣬��Ҫ�ش�
                clock_t currentTime = clock();
                if ((currentTime - start) / CLOCKS_PER_SEC > timeoutDuration) {
                    if (retryCount >= MAX_RETRY_COUNT) {
                        throw runtime_error("�ش������������ƣ������룺" + to_string(WSAGetLastError()));
                    }

                    // �������ϴη�������������ʱ��
                    double timeSinceLastSend = double(currentTime - lastSendTime) / CLOCKS_PER_SEC;
                    cout << "�� " << retryCount + 1 << " ���ش������ϴη��;��� " << timeSinceLastSend << " ��" << endl;

                    // �ش����ݰ�
                    if (TestFlag < TEST_TIME) //��ʱ�Ȳ��������ݰ�������ָ���˱��㷨
                    {
                        if (TestFlag == 0) {
                            cout << endl << "======����ָ���˱��㷨======" << endl;
                        }
                        TestFlag++;
                        cout << "TestFlag:" << TestFlag << endl;
                        // ָ���˱�
                        lastSendTime = clock();  // ������һ�η���ʱ��
                        timeoutDuration *= 2;  
                        retryCount++;  
                    }
                    else
                    {
                        // �ش����ݰ�
                        sendto(socketClient, buffer, sizeof(packet) + data_len, 0, (sockaddr*)&servAddr, servAddrlen);
                        lastSendTime = clock();  
                        timeoutDuration *= 2;  
                        retryCount++;  
                    }
                    
                }
            }

            // ���ȷ�ϰ�����ȷ��
            memcpy(&packet, buffer, sizeof(packet));
            if (packet.ack == (Seq_num + 1) % (256) && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
                cout << "�ɹ����Ͳ����յ�ȷ����Ӧ  Ack��" << int(packet.ack) << endl;
            }
            else {
                // �����δ���ܵ�����-�ش����ݣ�������һ�����ݰ���
                if (packet.ack == Seq_num || (compute_sum((WORD*)&packet, sizeof(packet)) != 0)) {
                    cout << "�����δ���ܵ����ݣ������ش���" << endl;
                    i--;
                    continue;
                }
                // ����˽��յ�������-У��ͳ��� ��Ҫ�ش�
                else {
                    throw runtime_error("�ͻ���δ�ɹ��������ݻ�����У��ʧ�ܣ���Ҫ�ش�");
                }
            }

            Seq_num = (Seq_num + 1) % 256;  // �������к�
        }

        // ���ݰ����ͽ��������ͽ�����־
        packet.tag = OVER;
        char* buffer = new char[sizeof(packet)];
        packet.checksum = 0;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer, &packet, sizeof(packet));
        sendto(socketClient, buffer, sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
        cout << "�ѷ������ݴ��������־" << endl;

        int retryCount = 0;
        int timeoutDuration = 1;  // ��ʼ��ʱʱ��Ϊ1��
        clock_t start = clock();  // ��¼����ʱ��

        // �ȴ�������־��ȷ��
        while (recvfrom(socketClient, buffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
            if ((clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                if (retryCount >= MAX_RETRY_COUNT) {
                    throw runtime_error("������־�ش�ʧ�ܳ�������Դ����������룺" + to_string(WSAGetLastError()));
                }
                // ��ʱ�ش�
                sendto(socketClient, buffer, sizeof(packet), 0, (sockaddr*)&servAddr, servAddrlen);
                cout << "������־�� " << retryCount + 1 << " ���ش���" << endl;
                start = clock();  
                timeoutDuration *= 2;  
                retryCount++;  
            }
        }

        memcpy(&packet, buffer, sizeof(packet));
        if (packet.tag == OVER && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
            cout << "�ɹ����յ�������־��ȷ��" << endl;
        }
        else {
            throw runtime_error("δ�ܳɹ����յ�������־��ȷ��");
        }
    }
    catch (const runtime_error& e)
    {
        cout << "�쳣����: " << e.what() << endl;
        mode = 0;
        ioctlsocket(socketClient, FIONBIO, &mode);  // �ָ�����ģʽ
        return;
    }
    mode = 0;
    ioctlsocket(socketClient, FIONBIO, &mode);  // ����ģʽ
    return;
}

// ��������
// ������socketServer - �������˵��׽��֣�clieAddr - �ͻ��˵�ַ�Ľṹ��clieAddrlen - �ͻ��˵�ַ�ṹ�ĳ���
// Mes - �洢���յ������ݵĻ������� MAX_SIZE - ÿ�����ݰ�������С
int RecvMessage(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen, char* Mes, int MAX_SIZE)
{
    Packet_Header packet;
    unique_ptr<char[]> buffer(new char[sizeof(packet) + MAX_SIZE]);
    int ack = 1;  // ȷ�����к�
    int seq = 0;
    long FileLength = 0;     // �����ܳ�
    int SegmentLength = 0;      // �������ݳ���

    try {
        // ѭ����������
        while (1) {
            // ��������
            while (recvfrom(socketServer, buffer.get(), sizeof(packet) + MAX_SIZE, 0, (sockaddr*)&clieAddr, &clieAddrlen) <= 0);
            memcpy(&packet, buffer.get(), sizeof(packet));

            // ����Ƿ���ȫ�ֽ�����־
            if (packet.tag == END && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
                cout << "�ѽ��յ�ȫ�ֽ�����־" << endl;
                return 999;
            }

            // ����Ƿ������ݴ��������־
            if (packet.tag == OVER && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
                cout << "�ѽ��յ����ݴ��������־" << endl;
                break;
            }

            // �����������ݰ�
            if (packet.tag == 0 && (compute_sum((WORD*)&packet, sizeof(packet)) == 0)) {
                // ������кţ�ȷ�����ݰ���˳��
                if (packet.seq != seq) {
                    // ������кŲ�ƥ�䣬�����ش�
                    Packet_Header temp;
                    temp.tag = 0;
                    temp.ack = seq;
                    temp.checksum = 0;
                    temp.checksum = compute_sum((WORD*)&temp, sizeof(temp));
                    memcpy(buffer.get(), &temp, sizeof(temp));
                    sendto(socketServer, buffer.get(), sizeof(temp), 0, (sockaddr*)&clieAddr, clieAddrlen);
                    cout << "�ѷ����ط�������ͻ���" << endl;
                    continue;// �����ȴ���һ�����ݰ�
                }
                // ��������
                SegmentLength = packet.datasize;
                cout << "��ʼ������Ϣ...... ���ݴ�С��" << SegmentLength << " �ֽڣ�" << " Tag��"
                    << int(packet.tag) << " Seq��" << int(packet.seq) << " CheckSum��" << int(packet.checksum) << endl;
                memcpy(Mes + FileLength, buffer.get() + sizeof(packet), SegmentLength);
                FileLength += SegmentLength;// ���½��������ܳ���
                // ����ȷ�ϻظ�
                packet.tag = 0;
                packet.ack = ack++;
                packet.seq = seq++;
                packet.datasize = 0;
                packet.checksum = 0;
                packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
                memcpy(buffer.get(), &packet, sizeof(packet));
                sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen);
                cout << "�ɹ����ղ�����ȷ��  ȷ�Ϻţ�" << int(packet.ack) << endl;
                // �������кź�ȷ�Ϻŵ�ѭ��
                seq = (seq > 255 ? seq - 256 : seq);
                ack = (ack > 255 ? ack - 256 : ack);
            }
        }
        // �������ݴ��������־
        packet.tag = OVER;
        packet.checksum = 0;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen);
        cout << "�ѷ������ݴ��������־" << endl;
    }
    catch (const runtime_error& e) {
        cout << "�쳣����: " << e.what() << endl;
        return -1;
    }

    return FileLength;  // ���ؽ��յ��������ܳ���
}

int main()
{
    // ��ʼ��Winsock
    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;
    int err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        cout << "Winsock ��ʼ��ʧ�ܣ�" << endl;
        return 1;
    }

    // ����UDP�׽���
    SOCKET client = socket(AF_INET, SOCK_DGRAM, 0);
    if (client == INVALID_SOCKET)
    {
        cout << "�׽��ִ���ʧ�ܣ������룺" << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }
    cout << "�ͻ����׽��ִ����ɹ���" << endl;

    // ���÷�������ַ
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));// ��ʼ����������ַ�ṹ��
    serveraddr.sin_family = AF_INET;// ����Э����ΪIPv4
    serveraddr.sin_port = htons(PORT);// ���÷������˿�
    inet_pton(AF_INET, IP, &serveraddr.sin_addr.s_addr);// ���÷�����IP��ַ
    
    // ѡ�����ģʽ
    cout << "��ѡ�����ģʽ������0 / ����1����" << endl;
    int label;
    cin >> label;

    // ���ӵ�������
    int length = sizeof(serveraddr);
    cout << "�����������������������..." << endl;
    if (Client_Server_Connect(client, serveraddr, length, label) == -1)
    {
        cout << "���ӽ���ʧ�ܡ�" << endl;
        closesocket(client);
        WSACleanup();
        return 1;
    }

    if (label == 0)// ����ģʽ
    {
        while (true)
        {
            cout << "=====================================================================" << endl;
            cout << "��ѡ��Ҫ���͵��ļ������� 'q' �˳�����" << endl;
            char InFileName[20];
            cout << "�����ļ�����";
            cin >> InFileName;

            // �������'q'���˳�
            if (InFileName[0] == 'q' && strlen(InFileName) == 1)
            {
                // ����������ͽ�����־
                Packet_Header packet;
                char buffer[sizeof(packet)];
                packet.tag = END;
                packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
                memcpy(buffer, &packet, sizeof(packet));
                sendto(client, buffer, sizeof(packet), 0, (sockaddr*)&serveraddr, length);
                cout << "������������ͽ�����־��" << endl;
                break;
            }
            // �Զ�����ģʽ����Ϊ InFileName ���ļ���file ���ں������ļ���ȡ������
            ifstream file(InFileName, ifstream::binary);
            if (!file)
            {
                cout << "�ļ���ʧ�ܣ�" << endl;
                continue;
            }

            // ��ȡ�ļ�����
            file.seekg(0, file.end);// ���ļ�ָ���ƶ����ļ���ĩβ
            int F_length = file.tellg();// ��ȡ��ǰ�ļ�ָ���λ�ã����ļ��Ĵ�С
            file.seekg(0, file.beg);// ���½��ļ�ָ���ƶ����ļ��Ŀ�ʼ��
            unique_ptr<char[]> FileBuffer(new char[F_length]);// ����һ���㹻��Ļ��������洢�����ļ�������
            file.read(FileBuffer.get(), F_length);// ���ļ��ж�ȡ F_length �ֽڵ����ݵ�������

            cout << "�ļ����ݴ�С��" << F_length << " �ֽڡ�" << endl;
            // �����ļ�����������
            SendMessage(client, serveraddr, length, InFileName, strlen(InFileName), DEFAULT_BUFFER_SIZE);
            clock_t start = clock();
            // �����ļ����ݵ�������
            SendMessage(client, serveraddr, length, FileBuffer.get(), F_length, DEFAULT_BUFFER_SIZE);
            clock_t end = clock();

            cout << "���õĶ�����: " << PACKET_LOSS_RATE * 100 << "%" << endl;
            cout << "���õ���ʱ: " << PACKET_DELAY_MS << " ����" << endl;

            cout << "������ʱ����" << (end - start) / CLOCKS_PER_SEC << " �롣" << endl;
            cout << "�����ʣ�" << static_cast<float>(F_length) / ((end - start) / CLOCKS_PER_SEC) << " �ֽ�/�롣" << endl;
            cout << "=====================================================================" << endl;
        }
    }
    else
    {
        while (true)
        {
            cout << "=====================================================================" << endl;
            cout << "�ȴ���������..." << endl;
            unique_ptr<char[]> F_name(new char[20]);
            unique_ptr<char[]> Message(new char[100000000]);

            int name_len = RecvMessage(client, serveraddr, length, F_name.get(), DEFAULT_BUFFER_SIZE);
            // ������յ������ݳ���Ϊ999��������ѭ��
            if (name_len == 999)
                break;
            // �����ļ�����
            int file_len = RecvMessage(client, serveraddr, length, Message.get(), DEFAULT_BUFFER_SIZE);
            string fileName(F_name.get(), name_len);
            cout << "���յ��ļ�����" << fileName << endl;
            cout << "���յ��ļ����ݴ�С��" << file_len << " �ֽڡ�" << endl;
            // �����ļ�
            ofstream file(fileName, ofstream::binary);
            if (!file)
            {
                cout << "�ļ���ʧ�ܣ�" << endl;
                continue;
            }
            file.write(Message.get(), file_len);
            file.close();

            cout << "���ݽ�����ϣ��ļ��ѱ��档" << endl;
            cout << "=====================================================================" << endl;
        }
    }
    // �Ͽ�����
    Client_Server_Disconnect(client, serveraddr, length);
    // ȷ���������ݶ�������
    this_thread::sleep_for(chrono::milliseconds(500));
    closesocket(client);
    WSACleanup();
    cout << "�����ѽ�����" << endl;
    system("pause");
    return 0;
}