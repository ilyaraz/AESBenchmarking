all:
	g++ aes_test.cpp -o aes_test -O3 -Wall -std=c++17 -march=native -lcrypto
