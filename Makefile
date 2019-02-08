CXX = gcc
CXXFLAGS = -g -Wall -DOPENSSL -lssl -lcrypto
RM = rm -rf

all: main.c
	$(CXX) $(CXXFLAGS) -o main main.c hash-file.h

clean:
	rm -f main
