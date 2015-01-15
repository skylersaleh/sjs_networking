/**
 *
 * SJS NETWORKING LIBRARY
 *
 * Very Simple Library for Socket Programming
 *
 * Copyright (c) 2014 Skyler Saleh
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 **/

#ifndef SJS_NETWORK_H
#define SJS_NETWORK_H

#include <iostream>
#include <unistd.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/poll.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdint.h>
#include <sys/uio.h>

typedef struct sjsn_PeerInfo{
    uint8_t port[10];
    uint8_t addr[54];
}sjsn_PeerInfo;


static void sjsn_initialize(){
    //No autokill on disconnect, yes this is a stupid POSIX feature.
    signal(SIGPIPE, SIG_IGN);
    
}
// get sockaddr, for either IPv4 or IPv6:

static void *sjsn_get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
static int sjsn_close_socket(int socket){
    if(socket!=-1)close(socket);
    return -1;
}
static int sjsn_set_timeout(int socket, float recv_timeout){
    struct timeval tv;
    
    tv.tv_sec = recv_timeout;  /* 30 Secs Timeout */
    tv.tv_usec = (recv_timeout-tv.tv_sec)*1e6;
    
    if(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval))==-1){
        perror("Failed to set socket timeout");
        return sjsn_close_socket(socket);
    };
    
    return socket;
}
static int sjsn_bind_server(const char* port, int listen_connections, float timeout = 1)
{
    int sockfd;  // listen on sock_fd
    struct addrinfo hints, *servinfo, *p;
    int yes=1;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP
    
    int rv = getaddrinfo(NULL, port, &hints, &servinfo);
    
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }
    
    
    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol);
        int r1 = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,sizeof(int));
        int r2 = bind(sockfd, p->ai_addr, p->ai_addrlen);
        
        if(sockfd>=0 && r1==0 && r2==0)break; //No errors in configuration
        
        sockfd = sjsn_close_socket(sockfd);
    }
    
    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        return -1;
    }
    
    freeaddrinfo(servinfo); // all done with this structure
    //sockfd=sjsn_set_timeout(sockfd,timeout);
    
    if(listen(sockfd,listen_connections) != 0){
        perror("Failed to listen");
        return sjsn_close_socket(sockfd);
    };
    return sockfd;
}

static int sjsn_accept_connection(int listen_fd, float timeout = 1, sjsn_PeerInfo * peer=NULL){
    if(peer){
        peer->addr[0]='\0';
        peer->port[0]='\0';
    }
    struct sockaddr_storage their_addr; // connector's address information
    char s[INET6_ADDRSTRLEN];
    socklen_t sin_size = sizeof their_addr;
    struct pollfd poll_r = {.events = POLLIN, .fd= listen_fd};
    
    int rv = poll(&poll_r, 1, timeout*1000);
    
    if (rv == -1) {
        perror("poll");
    }
    if(poll_r.revents&POLLIN){
        
        int new_fd = accept(listen_fd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            return -1;
        }
        inet_ntop(their_addr.ss_family, sjsn_get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
        printf("server: got connection from %s\n", s);
        
        if(peer){
            strncpy((char*)(peer->port), "", 10);
            strncpy((char*)(peer->addr), s, 54);
            peer->addr[53]='\0';
            peer->port[9]='\0';
            
        }
        
        return new_fd;
    }
    printf("Poll Timed-out\n");
    return -1;
    
}
static int sjsn_connect_socket(const char* addr, const char* port){
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    char s[INET6_ADDRSTRLEN];
    
    
    memset(&hints, 0, sizeof hints);
    
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    int rv = getaddrinfo(addr, port, &hints, &servinfo);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }
    
    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol);
        rv = connect(sockfd, p->ai_addr, p->ai_addrlen);
        
        if(sockfd!=-1&&rv !=-1)break; //We have a good connection
        
        sockfd=sjsn_close_socket(sockfd);
    }
    
    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return -1;
    }
    
    inet_ntop(p->ai_family, sjsn_get_in_addr((struct sockaddr *)p->ai_addr),s, sizeof(s));
    printf("client: connecting to %s\n", s);
    
    freeaddrinfo(servinfo); // all done with this structure
    return sockfd;
}
static int sjsn_send_data(int socket, unsigned char* data, int size){
    int byte_off = 0;
    while(byte_off<size){
        int s_res=send(socket,&data[byte_off],size-byte_off,0);
        if(s_res < 1){
            socket=sjsn_close_socket(socket);
            return socket;
        }
        byte_off+=s_res;
        
    }
    return socket;
}
static int sjsn_recv_data(int socket, unsigned char* data, int size){
    int byte_off = 0;
    while(byte_off<size){
        int s_res=recv(socket,&data[byte_off],size-byte_off,0);
        if(s_res < 1){
            socket=sjsn_close_socket(socket);
            return socket;
        }
        byte_off+=s_res;
        
    }
    return socket;
}
static int sjsn_send_data_chunked(int socket, unsigned char* data, int size){
   
    int state = 0;
    uint32_t s =size;
    //setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &state, sizeof(state));
    socket=sjsn_send_data(socket,(unsigned char*)&s,4);
    state = 1;
    socket= sjsn_send_data(socket,data,size);

    //setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &state, sizeof(state));
    //socket= sjsn_send_data(socket,data,0);

    return socket;
}
static int sjsn_recv_data_chunked(int socket, unsigned char* data, int max_size, int * read_size){
    uint32_t s=0;
    socket=sjsn_recv_data(socket,(unsigned char*)&s,4);
    if(s>max_size){
        s=max_size;
        printf("Buffer is too small to hold needed data\n");
    }
    
    
    
    socket=sjsn_recv_data(socket,data,s);
    if(socket==-1)s=0;
    *read_size=s;
    return socket;
}

typedef struct sjsn_NetworkID{
    uint32_t magic_number;
    uint32_t service_id;
    uint32_t function_id;
    uint8_t port[10];
    uint8_t padding[64-10-3*4];
}sjsn_NetworkID;



static int sjsn_bind_peer_listener(const char* port){
    int sockfd;  // listen on sock_fd
    struct addrinfo hints, *servinfo, *p;
    int yes=1;
    int rv;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP
    
    if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }
    
    
    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("server: socket");
            continue;
        }
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            return -1;
        }
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }
        
        break;
    }
    
    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        return -1;
    }
    //sjsn_set_timeout(sockfd,timeout);
    
    
    freeaddrinfo(servinfo); // all done with this structure
    return sockfd;
    
    
}
static int sjsn_connect_peer(int peer_listen_socket, uint32_t service_id, uint32_t function_id, float timeout=0.5,sjsn_PeerInfo* peer=NULL){
    if(peer){
        peer->addr[0]='\0';
        peer->port[0]='\0';
    }
    struct sockaddr_storage their_addr;
    memset(&their_addr, 0, sizeof(struct sockaddr_storage));
    
    unsigned int addr_len = sizeof their_addr;
    sjsn_NetworkID net_info;
    int numbytes=0;
    
    struct pollfd poll_r = {.events = POLLIN, .fd= peer_listen_socket};
    
    int rv = poll(&poll_r, 1, timeout*1000);
    
    if (rv == -1) {
        perror("poll");
    }
    if(poll_r.revents&POLLIN){
        
        if ((numbytes = recvfrom(peer_listen_socket, &net_info, sizeof(sjsn_NetworkID) , 0,
                                 (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            return -1;
        }
        if(numbytes != sizeof(sjsn_NetworkID)){
            perror("Wrong Size");
            return -1;
        }
        if(net_info.magic_number!=777){
            perror("Magic Number is Wrong");
            return -1;
        }
        if(net_info.service_id!=service_id|| net_info.function_id!= function_id){
            perror("Function and Service do not match");
            return -1;
        }
        struct sockaddr* addr = (struct sockaddr*)&their_addr;
        char addr_buffer[64];
        const char *res = inet_ntop( addr->sa_family, sjsn_get_in_addr(addr),addr_buffer,64);
        if(!res){
            perror("inet_ntop");
            return -1;
        }
        if(peer){
            strncpy((char*)(peer->port), (const char*)net_info.port, 10);
            strncpy((char*)(peer->addr), res, 54);

        }
        printf("Connecting to: %s:%s\n",res,(const char*)net_info.port);
        return sjsn_connect_socket(res,(const char*)net_info.port);
    }
    printf("Poll timed out\n");
    return -1;
}
static void sjsn_broadcast_peer_info(const char* connect_port, uint32_t service_id, uint32_t function_id, const char* broadcast_port){
    sjsn_NetworkID net_info = {.magic_number = 777, .service_id = service_id, .function_id = function_id};
    int i=0;
    for(i=0;i<10&&connect_port[i];++i)net_info.port[i]=connect_port[i];
    net_info.port[i]='\0';
    
    
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    int broadcast = 1;
    // this call is what allows broadcast packets to be sent:
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast,sizeof broadcast) == -1) {
        perror("setsockopt (SO_BROADCAST)");
        return;
    }
    struct sockaddr_in their_addr; // connector's address information
    struct hostent *he;
    
    if ((he=gethostbyname("255.255.255.255")) == NULL) {  // get the host info
        perror("gethostbyname");
        return;
    }
    
    their_addr.sin_family = AF_INET;     // host byte order
    their_addr.sin_port = htons(atoi(broadcast_port)); // short, network byte order
    their_addr.sin_addr = *((struct in_addr *)he->h_addr);
    memset(their_addr.sin_zero, '\0', sizeof their_addr.sin_zero);
    
    if ((sendto(sockfd, &net_info, sizeof(net_info), 0,
                (struct sockaddr *)&their_addr, sizeof their_addr)) == -1) {
        perror("sendto");
        return;
    }
    
    
    close(sockfd);
    
    
}
#endif



