
/*****************************************************************
//  
//  NAME:        Willard Peralta
//  
//  HOMEWORK:    4
//  
//  CLASS:       ICS 451
//  
//  INSTRUCTOR:  Ravi Narayan
//  
//  DATE:        October 8, 2019
//  
//  FILE:        client.c
//  
//  DESCRIPTION:
//  This file contains client source code for homework 4 
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
#include <time.h>

int printFlags(unsigned char message[]);

/*****************************************************************
//  Function name: main
//  
//  DESCRIPTION:   Setup client socket and receive jpeg file from server
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
    int clientSocket, portno, index;
    struct sockaddr_in serverAddr, my_addr;
    socklen_t addr_size, myaddr_size;
    unsigned char rawbytes[20];
    unsigned char syn[] = { 0xd3, 0xb2, 0x62, 0x6a, 0x54, 0x2e, 0xd6, 0xf5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x44, 0x70, 0xff, 0xff, 0x00, 0x00};
    unsigned char ack[] = { 0xd3, 0xb2, 0x62, 0x6a, 0x54, 0x2e, 0xd6, 0xf5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x44, 0x70, 0xff, 0xff, 0x00, 0x00};
    unsigned short myport;
    unsigned short destport;
    unsigned char myportseparatebytes[2];
    unsigned int randomseqnum = 0;

    /* Store command line argument portnumber and set destination port in syn and ack messages*/
    portno = atoi(argv[1]);
    destport = portno;
    syn[2] = (destport >> 8) & 0xFF;
    syn[3] = destport;
    ack[2] = (destport >> 8) & 0xFF;
    ack[3] = destport;
    /*---- Create the socket. The three arguments are: ----*/
    /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
    clientSocket = socket(PF_INET, SOCK_STREAM, 0);
  
    /*---- Configure settings of the server address struct ----*/
    /* Address family = Internet */
    serverAddr.sin_family = AF_INET;
    /* Set port number, using htons function to use proper byte order */
    serverAddr.sin_port = htons(portno);
    /* Set IP address to localhost */
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    /* Set all bits of the padding field to 0 */
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

    /*---- Connect the socket to the server using the address struct ----*/
    addr_size = sizeof serverAddr;
    connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);
   
    /*Get client source port number*/
    /*Adapted from https://stackoverflow.com/questions/4046616/sockets-how-to-find-out-what-port-and-address-im-assigned*/
    myaddr_size = sizeof(my_addr);
    getsockname(clientSocket, (struct sockaddr *)&my_addr, &myaddr_size);
    myport = ntohs(my_addr.sin_port);
    myportseparatebytes[0] = (myport >> 8) & 0xFF;
    myportseparatebytes[1] = myport;
    syn[0] = myportseparatebytes[0];
    syn[1] = myportseparatebytes[1];
    ack[0] = myportseparatebytes[0];
    ack[1] = myportseparatebytes[1];
    /*Generate random sequence number, code adapted from https://www.includehelp.com/c-programs/extract-bytes-from-int.aspx*/
    srand(time(NULL) + 37);
    randomseqnum = abs(rand() % 4292);  
    syn[4] = (randomseqnum & 0xFF);
    syn[5] = ((randomseqnum >> 8) & 0xFF);
    syn[6] = ((randomseqnum >> 16) & 0xFF);
    syn[7] = ((randomseqnum >> 24) & 0xFF); 
   
    /*Send SYN to server*/
    send(clientSocket, &syn, 20, 0);

    /*Receive SYN-ACK from server*/
    recv(clientSocket, &rawbytes, 20, 0);
    printf("\nPart 2 of TCP Handshake (SYN-ACK from server)\n-------Raw Bytes of TCP Header---------\n");
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
 
    /*Send ACK to server, sleep for one second to correctly send ACK*/
    sleep(1);
    /*Set acknowledgement number in synack message*/
    ack[8] = rawbytes[4];
    ack[9] = rawbytes[5];
    ack[10] = rawbytes[6];
    ack[11] = rawbytes[7] + 1;
    ack[4] = rawbytes[8];
    ack[5] = rawbytes[9];
    ack[6] = rawbytes[10];
    ack[7] = rawbytes[11];
    send(clientSocket, &ack, 20, 0);

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
