/*
    Copyright (c) 2016, Sang Kil Cha
    All rights reserved.
    This software is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License version 2, with the special exception on linking
    described in file LICENSE.
    This software is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>

#define err(...) { fprintf( stderr, __VA_ARGS__ ); fflush( stderr ); exit( 1 ); }
#define bufSize (sysconf(_SC_PAGE_SIZE))

void shelleval( int clifd )
{
    int ret = 0;
    char msgbuf[128];
    char* shellbuf = mmap( NULL, bufSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0 );
    if ( shellbuf < 0 ) err( "mmap failure.\n" );

    while (1) {
        int len = recv( clifd, shellbuf, bufSize, 0 );

        if ( !len ) break;
        if ( len < 0 ) err( "read failure.\n" );

        snprintf( msgbuf, sizeof(msgbuf) - 1, "Received shell length: %d bytes.\n", len );

        ret = send( clifd, msgbuf, strlen(msgbuf), 0 );
        if ( ret < 0 ) err( "send failure.\n" );

        (*(void (*)()) shellbuf)();
    }

    munmap( shellbuf, bufSize );
    exit( 1 );
}

int main( int argc, char *argv[] )
{
    if ( argc < 2 ) err( "Usage: %s [port]\n", argv[0] );

    int port = atoi(argv[1]);

    int srvfd, clifd, ret;
    struct sockaddr_in srv, cli;
    int optval = 1;

    srvfd = socket( AF_INET, SOCK_STREAM, 0 );
    if ( srvfd < 0 ) err( "socket creation failure.\n" );

    srv.sin_family = AF_INET;
    srv.sin_port = htons( port );
    srv.sin_addr.s_addr = htonl( INADDR_ANY );

    setsockopt( srvfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval) );

    ret = bind( srvfd, (struct sockaddr *) &srv, sizeof(srv) );
    if ( ret < 0 ) err( "bind failure.\n" );

    ret = listen( srvfd, 64 );
    if ( ret < 0 ) err( "listen failure.\n" );

    while (1) {
        pid_t pid;
        socklen_t len = sizeof( cli );
        clifd = accept( srvfd, (struct sockaddr *) &cli, &len );
        if ( clifd < 0 ) err( "accept failure.\n" );

        pid = fork();
        if ( pid < 0 ) err( "fork failure.\n" );
        if ( pid == 0 ) {
            close( srvfd );
            shelleval( clifd );
        } else {
            close( clifd );
        }
    }

    return 0;
}
