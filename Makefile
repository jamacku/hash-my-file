CXX = gcc
CXXFLAGS = -g -Wall -DOPENSSL -lssl -lcrypto
RM = rm -rf

all: main.c
	$(CXX) $(CXXFLAGS) -o main main.c

clean:
	rm -f main
