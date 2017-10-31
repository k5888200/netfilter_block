TARGET = netfilter_block

$(TARGET) : main.o
	g++ -o $(TARGET) main.o -lnetfilter_queue

main.o : main.cpp
	g++ -c -o main.o main.cpp -std=c++11

clean :
	rm -f *.o netfilter_block


