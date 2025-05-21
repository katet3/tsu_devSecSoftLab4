CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LDFLAGS = -lcrypto
TARGET = file_encryptor
SRC = cryptor.cc

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean