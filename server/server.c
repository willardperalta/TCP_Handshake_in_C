/*****************************************************************
//
//  NAME:        Willard Peralta
//
//  HOMEWORK:    7
//
//  CLASS:       ICS 451
//
//  INSTRUCTOR:  Ravi Narayan
//
//  DATE:        November 1, 2019
//
//  FILE:        server.c
//
//  DESCRIPTION:
//   This file contains source code for homework 7 
//
****************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

int printFlags(unsigned char message[]);

/*****************************************************************
//
//  Function name: main
//
//  DESCRIPTION:   TCP handshake, server sends ACK
//                 Code adapted from:
//                 https://www.programminglogic.com/example-of-client-server-program-in-c-using-sockets-and-tcp/
//
//  Parameters:    argc, *argv                 
//
//  Return values:  0 : success
//
****************************************************************/

int main(int argc, char *argv[])
{
    int welcomeSocket, newSocket, clientConnected, portno, index;
    unsigned char rawbytes[20];
    struct sockaddr_in serverAddr;
    struct sockaddr_storage serverStorage;
    socklen_t addr_size;
    unsigned short serverport;
    unsigned char synack[] = { 0x62, 0x6a, 0xd3, 0xb2, 0x65, 0xb1, 0x56, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x44, 0x70, 0xff, 0xff, 0x00, 0x00};
    unsigned int randomseqnum = 0;   

    /* Store command line argument portnumber and set source port in synack message*/
    portno = atoi(argv[1]);
    serverport = portno;
    synack[0] = (serverport >> 8) & 0xFF;
    synack[1] = serverport;

    /* Create the socket with Internet domain, Stream socket, Default protocol (TCP in this case) */
    welcomeSocket = socket(PF_INET, SOCK_STREAM, 0);
 
    /* Address family = Internet */
    serverAddr.sin_family = AF_INET;
    /* Set port number, using htons function to use proper byte order */
    serverAddr.sin_port = htons(portno);
    /* Set IP address to localhost */
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    /* Set all bits of the padding field to 0 */
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

    /* Bind the address struct to the socket */
    bind(welcomeSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

    printf("\nListening...\n\n");

    /* Listen on the socket and continue to run */
    while(1)
    {
        clientConnected = listen(welcomeSocket,1);
        
        /* A client has connected */
        if(clientConnected == 0)
        {
            /* Accept call creates a new socket for the incoming connection */
            addr_size = sizeof serverStorage;
            newSocket = accept(welcomeSocket, (struct sockaddr *) &serverStorage, &addr_size);

            /*Receive SYN from client*/
            recv(newSocket, &rawbytes, 20, 0);
            printf("\nPart 1 of TCP Handshake (SYN from client)\n-------Raw Bytes of TCP Header---------\n");
            for(index = 0; index < 20; index++)
            {
                printf("%.2x", rawbytes[index]);
            }
            printf("\n-------Human Readable TCP Header-------\n");
            printf("Source TCP port number: %d\n", (rawbytes[0] * 0x100) + rawbytes[1]);
            printf("Destination port number: %d\n", (rawbytes[2] * 0x100) + rawbytes[3]);
            printf("Sequence Number: %d\n", (rawbytes[4] * 0x1000000) + (rawbytes[5] * 0x10000) + (rawbytes[6] * 0x100) + rawbytes[7]);
            printf("Acknowledgement number: %d\n", (rawbytes[8] * 0x1000000) + (rawbytes[9] * 0x10000) + (rawbytes[10] * 0x100) + rawbytes[11]);
            printf("TCP data offset: %d\n", rawbytes[12]);
            printf("Reserved data: %d\n", rawbytes[12]);
            printf("Control flags: \n");
            printFlags(rawbytes);

            printf("Window size: %d\n", (rawbytes[14] * 0x100) + rawbytes[15]);
            printf("TCP Checksum: %d\n", (rawbytes[16] * 0x100) + rawbytes[17]);
            printf("Urgent Pointer: %d\n\n", (rawbytes[18] * 0x100) + rawbytes[19]);

            /*Set destination port number, which was the source port in the initial SYN message*/
            synack[2] = rawbytes[0];
            synack[3] = rawbytes[1];
            /*Generate random sequence number, code adapted from https://www.includehelp.com/c-programs/extract-bytes-from-int.aspx*/
            srand(time(NULL));
            randomseqnum = abs((rand() % 6296));
            synack[4] = (randomseqnum & 0xFF);
            synack[5] = ((randomseqnum >> 8) & 0xFF);
            synack[6] = ((randomseqnum >> 16) & 0xFF);
            synack[7] = ((randomseqnum >> 24) & 0xFF); 
            /*Set acknowledgement number in synack message*/
            synack[8] = rawbytes[4];
            synack[9] = rawbytes[5];
            synack[10] = rawbytes[6];
            synack[11] = rawbytes[7] + 1;
            /* Send SYN-ACK to client */
            send(newSocket, &synack, 20, 0);

            /*Receive ACK from client*/
            recv(newSocket, &rawbytes, 20, 0);
            printf("\nPart 3 of TCP Handshake (ACK from client)\n-------Raw Bytes of TCP Header---------\n");
            for(index = 0; index < 20; index++)
            {
                printf("%.2x", rawbytes[index]);
            }
            printf("\n-------Human Readable TCP Header-------\n");
            printf("Source TCP port number: %d\n", (rawbytes[0] * 0x100) + rawbytes[1]);
            printf("Destination port number: %d\n", (rawbytes[2] * 0x100) + rawbytes[3]);
            printf("Sequence Number: %d\n", (rawbytes[4] * 0x1000000) + (rawbytes[5] * 0x10000) + (rawbytes[6] * 0x100) + rawbytes[7]);
            printf("Acknowledgement number: %d\n", (rawbytes[8] * 0x1000000) + (rawbytes[9] * 0x10000) + (rawbytes[10] * 0x100) + rawbytes[11]);
            printf("TCP data offset: %d\n", rawbytes[12]);
            printf("Reserved data: %d\n", rawbytes[12]);
            printf("Control flags: \n");
            printFlags(rawbytes);
            
            printf("Window size: %d\n", (rawbytes[14] * 0x100) + rawbytes[15]);
            printf("TCP Checksum: %d\n", (rawbytes[16] * 0x100) + rawbytes[17]);
            printf("Urgent Pointer: %d\n\n", (rawbytes[18] * 0x100) + rawbytes[19]);

            printf("\nNew client connected.\n");
            close(newSocket);

        } 
    }  
  
 
    return 0;
}

int printFlags(unsigned char message[])
{
    unsigned char flags = message[13];

    if((flags & 0x01) == 0x01)
    {
        printf("FIN\n");
    }

    if((flags & 0x02) == 0x02)
    {
        printf("SYN\n");
    }

    if((flags & 0x04) == 0x04)
    {
        printf("RST\n");
    }

    if((flags & 0x08) == 0x08)
    {
        printf("PSH\n");
    }

    if((flags & 0x10) == 0x10)
    {
        printf("ACK\n");
    }

    if((flags & 0x20) == 0x20)
    {
        printf("URG\n");
    }

    if((flags & 0x40) == 0x40)
    {
        printf("ECE\n");
    }

    if((flags & 0x80) == 0x80)
    {
        printf("CWR\n");
    }

    return 0;
}
