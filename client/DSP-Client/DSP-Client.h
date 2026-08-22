#pragma once
#include <iostream>
#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

std::string extractStringValJSON(std::string& line);

std::string extractIntValJSON(std::string& line);

void addUint32ToBuffer(std::vector<uint8_t>& buffer, uint32_t value);

void addStringToBuffer(std::vector<uint8_t>& buffer, const std::string& str, bool dynamic, size_t size);

uint16_t extractUint16(std::vector<uint8_t>& buffer, uint16_t offset);

uint32_t extractUint32(std::vector<uint8_t>& buffer, uint32_t offset);

#pragma pack(push, 1)
struct RequestHeader {
	uint8_t clientID[16];
	uint8_t version;
	uint16_t code;
	uint32_t payloadSize;
};
#pragma pack(pop)