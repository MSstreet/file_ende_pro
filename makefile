CC = gcc

INC = -I./include/
LIB_DIRS = -L./lib/

TARGET = OperEndefile
LIBS = -lEdgeCrypto

$(TARGET) : main.c libEndefile libEdgeCrypto.so
	$(CC) -g -o $(TARGET) main.c -L./ -lEdgeCrypto -lEndefile $(INC)

libEndefile : endefile.o
	gcc -shared -o libEndefile.so endefile.o

endefile.o : endefile.c
	gcc -fPIC -c endefile.c

clean :
	rm -f *.o
	rm -f $(TARGET)

