/*���ܰ������������ӡ�����⡢ȷ���ش��ȡ��������Ʋ���ͣ�Ȼ���*/

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
int Client_Server_Connect(SOCKET& socketServer, SOCKADDR_IN& clieAddr, int& clieAddrlen)
{
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
                cout << "�ɹ����յ�һ��������Ϣ! " << endl;
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
        cout << "��ʼ�ĳ�ʱʱ��: " << timeoutDuration << " ��" << endl;

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
                cout << "��ʱ�������ش�ACK" << endl;
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

        cout << "����RTT: " << sampleRTT << " ��" << endl;
        cout << "����RTT: " << estimatedRTT << " ��" << endl;
        cout << "RTTƫ��: " << devRTT << " ��" << endl;
        cout << "���º�ĳ�ʱʱ��: " << timeoutDuration << " ��" << endl;

        // �ָ�Ϊ����ģʽ
        mode = 0;
        ioctlsocket(socketServer, FIONBIO, &mode);

        cout << "�ɹ����͵ڶ���������Ϣ" << endl;

        // �����յ���ACK_SYN���Ƿ���ȷ
        memcpy(&packet, buffer.get(), sizeof(packet));
        if (!(packet.tag == ACK_SYN && (compute_sum((WORD*)&packet, sizeof(packet)) == 0))) {
            throw runtime_error("�޷����տͻ��˻ش������ɿ����ӣ������룺" + to_string(WSAGetLastError()));
        }
        cout << "�ɹ��յ�������������Ϣ" << endl;
        cout << "�ͻ��������˳ɹ������������ֽ������ӣ����Կ�ʼ����/��������" << endl;
    }
    catch (const runtime_error& e) {
        cout << "�쳣����: " << e.what() << endl;
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
                cout << "����˳ɹ����յ��ͻ��˵ĵ�һ�λ�����Ϣ(FIN_ACK)" << endl;
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
        cout << "����˳ɹ����͵ڶ��λ�����Ϣ(ACK)" << endl;

        // ����˴���δ����������ݣ�����еĻ���

        // �����Σ��������ͻ��˷��ͻ�����Ϣ��FIN_ACK��
        packet.tag = FIN_ACK;
        packet.checksum = compute_sum((WORD*)&packet, sizeof(packet));
        memcpy(buffer.get(), &packet, sizeof(packet));
        if (sendto(socketServer, buffer.get(), sizeof(packet), 0, (sockaddr*)&clieAddr, clieAddrlen) == -1) {
            throw runtime_error("����˷���FIN_ACKʧ�ܣ������룺" + to_string(WSAGetLastError()));
        }
        cout << "����˳ɹ����͵����λ�����Ϣ(FIN_ACK)" << endl;

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
                    cout << "�ȴ������λ��ֳ�ʱ�����ڽ��е� " << retryCount << " ���ش�" << endl;
                    start = clock(); // ���ü�ʱ��
                    timeoutDuration *= 2; // ָ���˱�
                }
            }
            else
            {
                cout << "����˳ɹ��յ��ͻ��˵ĵ��Ĵλ�����Ϣ(ACK)" << endl;
                cout << "�ͻ��������˳ɹ��Ͽ����ӣ�" << endl;
                break;
            }
        }
    }
    catch (const runtime_error& e) {
        cout << "�Ͽ����ӹ����з����쳣: " << e.what() << endl;
        return -1;
    }

    return 1;
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

// �������ݣ�����û�ж�������ʱ�ͳ�ʱ��ʱ�ش����ԣ�
// socketClient - �ͻ��˵��׽��֣�servAddr - �������ĵ�ַ��Ϣ��servAddrlen - ��������ַ��Ϣ�ĳ��ȣ�
// Message - Ҫ���͵���Ϣ��ָ�룬mes_size - ��Ϣ�Ĵ�С��MAX_SIZE - ÿ�����ݰ�������С
void SendMessage(SOCKET& socketClient, SOCKADDR_IN& servAddr, int& servAddrlen, char* Message, int mes_size, int MAX_SIZE)
{
    int packet_num = mes_size / (MAX_SIZE)+(mes_size % MAX_SIZE != 0);// ������Ҫ�����ݰ�����
    int Seq_num = 0;  //��ʼ�����к�
    Packet_Header packet;
    u_long mode = 1;
    ioctlsocket(socketClient, FIONBIO, &mode);  // ������ģʽ

    try
    {
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

            // ��������
            sendto(socketClient, buffer, sizeof(packet) + data_len, 0, (sockaddr*)&servAddr, servAddrlen);
            cout << "��ʼ������Ϣ...... ���ݴ�С��" << data_len << " �ֽڣ�" << " Tag��" << int(packet.tag) << " Seq��" << int(packet.seq) << " CheckSum��" << int(packet.checksum) << endl;

            int retryCount = 0;
            int timeoutDuration = 1;  // ��ʼ��ʱʱ��Ϊ1��
            clock_t start = clock();  // ��¼����ʱ��

            // �ȴ�ȷ����Ӧ
            while (recvfrom(socketClient, buffer, sizeof(packet), 0, (sockaddr*)&servAddr, &servAddrlen) <= 0) {
                if ((clock() - start) / CLOCKS_PER_SEC > timeoutDuration) {
                    if (retryCount >= MAX_RETRY_COUNT) {
                        throw runtime_error("�ش������������ƣ������룺" + to_string(WSAGetLastError()));
                    }
                    // ��ʱ�ش�
                    sendto(socketClient, buffer, sizeof(packet) + data_len, 0, (sockaddr*)&servAddr, servAddrlen);
                    cout << "�� " << retryCount + 1 << " ���ش���" << endl;
                    start = clock();  // ���ü�ʱ��
                    timeoutDuration *= 2;  // ָ���˱ܣ���ʱʱ��ӱ�
                    retryCount++;  // �����ش�����
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

        //���ͽ�����־
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
                retryCount++;
                if (retryCount > MAX_RETRY_COUNT) {
                    throw runtime_error("������ش������������ƣ������룺" + to_string(WSAGetLastError()));
                }
                // ��ʱ�ش�
                cout << "����˵ȴ����Ĵλ�����Ϣ��ʱ�����ڽ��е� " << retryCount << " ���ش�" << endl;
                // �ش��߼���������Ҫ��
                start = clock();  // ���ü�ʱ��
                timeoutDuration *= 2;  // ָ���˱ܣ���ʱʱ��ӱ�
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
    SOCKET server = socket(AF_INET, SOCK_DGRAM, 0);
    if (server == SOCKET_ERROR)
    {
        cout << "�׽��ִ���ʧ�ܣ������룺" << WSAGetLastError() << endl;
        WSACleanup();
        return 0;
    }
    cout << "������׽��ִ����ɹ�" << endl;

    // ���÷�������ַ
    SOCKADDR_IN addr;
    memset(&addr, 0, sizeof(sockaddr_in)); // ��ʼ����ַ�ṹ
    addr.sin_family = AF_INET; // ���õ�ַ����ΪIPv4
    addr.sin_port = htons(PORT); // ���ö˿�
    inet_pton(AF_INET, IP, &addr.sin_addr.s_addr); // ����IP��ַ
    
    // ���׽���
    if (bind(server, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        cout << "��ʧ�ܣ������룺" << WSAGetLastError() << endl;
        WSACleanup();
        return 0;
    }

    // �ȴ��ͻ�������
    int length = sizeof(addr);
    cout << "�ȴ��ͻ�����������..." << endl;
    int label = Client_Server_Connect(server, addr, length);

    if (label == 0) { //��������
        while (true) {
            cout << "=====================================================================" << endl;
            cout << "�ȴ���������..." << endl;

            unique_ptr<char[]> F_name(new char[20]);
            unique_ptr<char[]> Message(new char[100000000]);
            int name_len = RecvMessage(server, addr, length, F_name.get(), DEFAULT_BUFFER_SIZE);

            if (name_len == 999) { // ����Ƿ��ǽ�����־
                cout << "���յ�ȫ�ֽ�����־���˳�����ѭ��" << endl;
                break;
            }

            int file_len = RecvMessage(server, addr, length, Message.get(), DEFAULT_BUFFER_SIZE); // �����ļ�����
            string filename(F_name.get(), name_len); // �����ļ����ַ���
            cout << "���յ����ļ�����" << filename << endl;
            cout << "���յ����ļ���С��" << file_len << " �ֽ�" << endl;

            ofstream file_stream(filename, ios::binary); // �����ļ���
            if (!file_stream) { // ����ļ��Ƿ�򿪳ɹ�
                cout << "�ļ���ʧ��" << endl;
                continue; // ��ʧ�ܣ�������һ��ѭ��
            }

            file_stream.write(Message.get(), file_len);// д���ļ�����
            cout << "���ݽ�����ϣ��ļ��ѱ���" << endl;
            cout << "=====================================================================" << endl;
        }
    }
    else if (label == 1) { // ��������
        while (true) {
            cout << "=====================================================================" << endl;
            cout << "ѡ��Ҫ���͵��ļ�..." << endl;

            char InFileName[20];
            cout << "�����ļ��������� 'q' �˳���:";
            cin >> InFileName;

            if (strcmp(InFileName, "q") == 0) { // ����Ƿ������˳�ָ��
                Packet_Header packet;
                unique_ptr<char[]> buffer(new char[sizeof(packet)]); // ����������
                packet.tag = END; // ���ý�����־
                packet.checksum = compute_sum((WORD*)&packet, sizeof(packet)); // ����У���
                memcpy(buffer.get(), &packet, sizeof(packet)); // ���Ƶ�������
                sendto(server, buffer.get(), sizeof(packet), 0, (sockaddr*)&addr, length); // ���ͽ�����־
                cout << "����ȫ�ֽ�����־��������" << endl;
                break; // �˳�ѭ��
            }

            ifstream file_stream(InFileName, ios::binary | ios::ate); // ���ļ�
            if (!file_stream) { // ����ļ��Ƿ�򿪳ɹ�
                cout << "�ļ���ʧ��" << endl;
                continue; // ��ʧ�ܣ�������һ��ѭ��
            }

            int F_length = static_cast<int>(file_stream.tellg()); // ��ȡ�ļ���С
            file_stream.seekg(0, ios::beg); // �����ļ�ָ��
            unique_ptr<char[]> FileBuffer(new char[F_length]); // �����ļ����ݻ�����
            file_stream.read(FileBuffer.get(), F_length); // ��ȡ�ļ�����

            cout << "�����ļ����ݴ�С��" << F_length << " �ֽ�" << endl;

            SendMessage(server, addr, length, InFileName, strlen(InFileName), DEFAULT_BUFFER_SIZE); // �����ļ���
            clock_t start = clock(); // ��¼��ʼʱ��
            SendMessage(server, addr, length, FileBuffer.get(), F_length, DEFAULT_BUFFER_SIZE); // �����ļ�����
            clock_t end = clock(); // ��¼����ʱ��
            cout << "��������ʱ��" << static_cast<double>(end - start) / CLOCKS_PER_SEC << " ��" << endl;
            cout << "�����ʣ�" << static_cast<double>(F_length) / ((end - start) / CLOCKS_PER_SEC) << " �ֽ�/��" << endl;
            cout << "=====================================================================" << endl;
        }
    }

    // �Ͽ����Ӳ�������Դ
    Client_Server_Disconnect(server, addr, length); // �Ͽ�����
    closesocket(server); // �ر��׽���
    WSACleanup(); // ����Winsock
    cout << "�����ѽ�����" << endl;
    system("pause"); 
    return 0;
}
