#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define P 8000  // port number to bind the socket to you can replace with the desired port number you went
#define BUFSIZE 1024  // buffer size to store received datagrams

int set_Socket_And_Server();

/*
argc that stores the number of arguments passed to the program when it is executed
argv it is an array of character pointers that stores the actual arguments passed to the program when it is executed:
    argv[0] always contains the name of the program being executed
    argv[1] contains the hostname that was passed as an argument
*/
int main(int argc, char **argv) {
    int socket_for_sending, socket_for_receiving;  // two sockets to be used for sending and receiving datagrams
    struct sockaddr_in server_for_sending, server_for_receiving;  // structs to store server information
    struct hostent *hp; 
    char buf[BUFSIZE];  // buffer to store received datagrams

    // checks if the number of arguments passed to the program is equal to 2
    if (argc != 2) {
        fprintf(stderr, "Usage: %s hostname\n", argv[0]);
        exit(1);
    }

    // create socket and set up server for sending information
    set_Socket_And_Server(&socket_for_sending, &server_for_sending, P+1);
    if ((hp = gethostbyname(argv[1])) == NULL) {
        fprintf(stderr, "Error: host %s not found\n", argv[1]);
        exit(1);
    }
    memcpy((char *)&server_for_sending.sin_addr, hp->h_addr, hp->h_length);
    
    // create socket and set up server for receiving information
    set_Socket_And_Server(&socket_for_receiving, &server_for_receiving, P);

    // bind socket_for_receiving to port P
    if (bind(socket_for_receiving, (struct sockaddr *)&server_for_receiving, sizeof(server_for_receiving)) < 0) {
        perror("bind\n");
        exit(1);
    }

    // enter infinite loop for receiving and forwarding datagrams
    while (1) {
        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);

        printf("We are waiting for a message\n");

        // receive datagram from port P
        int n = recvfrom(socket_for_receiving, buf, BUFSIZE, 0, (struct sockaddr *)&client, &client_len);
        if (n < 0) {
            perror("recvfrom\n");
            exit(1);
        }

        printf("We received a message\n");

        // sample random number to decide whether to forward the datagram
        float rand_num = ((float)random())/((float)RAND_MAX);
        if (rand_num > 0.5) {

            printf("The random number = %f > 0.5 => therefore we will send a message back\n", rand_num);

            // forward the datagram to port P+1
            if (sendto(socket_for_sending, buf, n, 0, (struct sockaddr *)&server_for_sending, sizeof(server_for_sending)) < 0) {
                perror("sendto\n");
                exit(1);
            }
        } else {

            // discard the datagram and go back to waiting for another incoming datagram
            printf("The random number = %f < 0.5 => therefore we will not send a message back\n", rand_num);
        }
    }
    return 0;
}


int set_Socket_And_Server(int* Socket, struct sockaddr_in* Server, int Port)
{
    if ((*(Socket) = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Error in the socket for receiving\n");
        exit(1);
    }

    // set up server_for_sending information
    memset((char *)Server, 0, sizeof(Server));
    Server->sin_family = AF_INET;
    Server->sin_addr.s_addr = htonl(INADDR_ANY);
    Server->sin_port = htons(Port);
    return 0;
}




// // create socket for sending datagrams
// if ((socket_for_sending = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
//     perror("Error in the socket for sending\n");
//     exit(1);
// }

// // create socket for receiving datagrams
// if ((socket_for_receiving = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
//     perror("Error in the socket for receiving\n");
//     exit(1);
// }

// // set up server_for_sending information
// memset((char *)&server_for_sending, 0, sizeof(server_for_sending));
// server_for_sending.sin_family = AF_INET;
// if ((hp = gethostbyname(argv[1])) == NULL) {
//     fprintf(stderr, "Error: host %s not found\n", argv[1]);
//     exit(1);
// }
// memcpy((char *)&server_for_sending.sin_addr, hp->h_addr, hp->h_length);
// server_for_sending.sin_port = htons(P + 1);

// // set up server_for_receiving information
// memset((char *)&server_for_receiving, 0, sizeof(server_for_receiving));
// server_for_receiving.sin_family = AF_INET;
// server_for_receiving.sin_addr.s_addr = htonl(INADDR_ANY);
// server_for_receiving.sin_port = htons(P);
