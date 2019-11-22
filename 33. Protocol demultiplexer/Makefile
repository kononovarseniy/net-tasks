CC=gcc
FLAGS=-Wall
SOURCE=main.c buffer.c protocol.c tls.c http.c ssh.c

all: bin $(SOURCE)
	$(CC) $(FLAGS) $(SOURCE) -o bin/pd
bin:
	mkdir bin
