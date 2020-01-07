#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <errno.h>

#ifdef __linux__
#include <unistd.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif


#pragma pack(1)
typedef struct
{
	unsigned char ip_v : 4,
		ip_hl : 4;
	unsigned char ip_tos;       //1 Byte
	unsigned short int ip_len;  //2 Byte
	unsigned short int ip_id;   //2 Byte
	unsigned short int ip_off;  //2 Byte
	unsigned char ip_ttl;       //1 Byte
	unsigned char ip_p;         //1 Byte
	unsigned short int ip_sum;  //2 Byte
	unsigned int ip_src;        //4 Byte
	unsigned int ip_dst;        //4 Byte
} ipv4_header;
#pragma pack(8)

#pragma pack(1)
typedef struct
{
	unsigned short hwtype;
	unsigned short proto_type;
	unsigned char hwsize;
	unsigned char proto_size;
	unsigned short cmd;
	unsigned char request_mac[6];
	unsigned int sender_ip;
	unsigned char target_mac[6];
	unsigned int target_ip;	
} arp_request_t;
#pragma pack(8)

#ifdef WIN32
#include <winsock.h>

typedef int socklen_t;

int inet_pton(int af, const char *server, void *vaddr)
{
	in_addr *addr = (in_addr *)vaddr;
	struct hostent *host = gethostbyname(server);
	if (host)
		*addr = *((struct in_addr *)*host->h_addr_list);
	return 1;
}
#endif


typedef struct
{
	ipv4_header ipv4;
	arp_request_t resp;
} response_t;


// 16 bit one's complement
unsigned short checksum(void *b, int len)
{
	unsigned short *buf = (unsigned short *)b;
	unsigned int sum = 0;
	unsigned short result;

	for (sum = 0; len > 1; len -= 2)
	{
		sum += *buf++;
	}
	if (len == 1)
	{
		sum += *(unsigned char*)buf;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

int send_arp(char *request_ip, char *src_ip, char *request_mac)
{
	arp_request_t arp;



	inet_pton(AF_INET, src_ip, &arp.sender_ip);
	inet_pton(AF_INET, request_ip, &arp.target_ip);
	
	response_t *response = NULL;
	char buffer[4096];
	int sock;
	int attempt = 1;
	struct sockaddr_in addr;
	struct hostent *hname;

	// convert host to ip
	hname = gethostbyname("255.255.255.255");
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = hname->h_addrtype;
	addr.sin_port = 0;
	addr.sin_addr.s_addr = *(long*)hname->h_addr;

	// get raw socket
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0)
	{
		perror("socket failed");
		return -1;
	}

	int option = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &option, sizeof(option)) < 0)
	{
        	perror("broadcast failed");
	}

	unsigned int size = sizeof(addr);

	memset(&arp, 0, sizeof(arp_request_t));
	arp.hwtype = 1;
	arp.proto_type = 0x800;
	arp.hwsize = 6;
	arp.proto_size = 4;
	arp.cmd = 1;
	arp.request_mac[0] = request_mac[0];
	arp.request_mac[1] = request_mac[1];
	arp.request_mac[2] = request_mac[2];
	arp.request_mac[3] = request_mac[3];
	arp.request_mac[4] = request_mac[4];
	arp.request_mac[5] = request_mac[5];
	if (sendto(sock, (char *)&arp, sizeof(arp_request_t), 0, (struct sockaddr*)&addr, sizeof(addr)) <= 0)
	{
		perror("sendto failed");
#ifdef WIN32
		int ret = WSAGetLastError();

		switch (ret)
		{
		case WSAETIMEDOUT:
			printf("Fatal Error: Connection timed out.\n");
			break;
		case WSAECONNREFUSED:
			printf("Fatal Error: Connection refused\n");
			break;
		case WSAEHOSTUNREACH:
			printf("Fatal Error: Router sent ICMP packet (destination unreachable)\n");
			break;
		default:
			printf("Fatal Error: %d\n", ret);
			break;
		}
#endif
		return -2;
	}
	struct timeval timeout;
	fd_set read_set;
	FD_ZERO(&read_set);
	FD_SET(sock, &read_set);
	timeout.tv_sec = 0;
	timeout.tv_usec = 200000;
		int ret = select(sock + 1, &read_set, NULL, NULL, &timeout);
	if (ret < 0)
	{
		perror("select() failed");
		return -1;
	}
	else if (ret == 0)
	{
		printf("timed out\r\n");
		return -1;
	}

	if (FD_ISSET(sock, &read_set))
	{
		memset(buffer, 0, 4096);
		response = (response_t *)&buffer;
		ret = recvfrom(sock, (char *)response, 4096, 0, (struct sockaddr*)&addr, (socklen_t *)&size);
			if (ret > 0)
		{
			char ip_resp[64];
			inet_ntop(AF_INET, &response->ipv4.ip_src, ip_resp, 64);
			printf("Response received from %s echo: %d\r\n", ip_resp, response->resp.cmd);
			return 0;
		}
	}
}
int main(int argc, char *argv[])
{
	int ret = 0;

#ifdef WIN32
	static WSADATA	wsadata;

	WSAStartup(MAKEWORD(2, 2), &wsadata);
#endif

	if (argc < 2)
	{
		printf("usage: %s <ip> [ip] ...\n", argv[0]);
		return -1;
	}

	for (int i = 1; i < argc; i++)
	{
		char request_mac[] = { 0x00, 0x08, 0xe3, 0xff, 0xfd, 0x00 };

	
		int result = send_arp("138.126.17.229", "138.126.16.30", &request_mac[0]);
		if (result == 0)
		{
			return 0;
		}

		ret |= result;
	}

#ifdef WIN32
	WSACleanup();
#endif

	return ret;
}


