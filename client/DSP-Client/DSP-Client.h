#pragma once
#include <iostream>
#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>

#pragma pack(push, 1)
struct RequestHeader {
	uint8_t clientID[16];
	uint8_t version;
	uint16_t code;
	uint32_t payloadSize;
};
#pragma pack(pop)

struct ClientState {
	uint8_t clientID[16];
	CryptoPP::RSA::PrivateKey rsapriv;
	std::vector<uint8_t> encrypted_aes;
};

std::string extractStringValJSON(std::string& line);

std::string extractIntValJSON(std::string& line);

void addUint32ToBuffer(std::vector<uint8_t>& buffer, uint32_t value);

void addStringToBuffer(std::vector<uint8_t>& buffer, const std::string& str, size_t size, bool dynamic = false, bool isBinary = false);

uint16_t extractUint16(std::vector<uint8_t>& buffer, uint16_t offset);

uint32_t extractUint32(std::vector<uint8_t>& buffer, uint32_t offset);

std::string createRSAPairAndReturnPublicKey(ClientState& state);