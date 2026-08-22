#include "DSP-Client.h"
using boost::asio::ip::tcp;

void sendRequest(tcp::socket& socket, uint16_t code, const std::string& name, const std::string& key = "", const uint32_t contectSize = 0,
    const uint32_t origFileSize = 0, const uint32_t packetInfo = 0, const std::string& encryptedFile = "") {

    RequestHeader header;
    
    for (int i = 0; i < 16; i++) {
        header.clientID[i] = 0;
    }

    header.version = 3;
    header.code = code;
    std::vector<uint8_t> payload;
    std::vector<boost::asio::const_buffer> buffers;

    if (code == 825 || code == 827 || code == 900 || code == 901 || code == 902) {
        addStringToBuffer(payload, name, 0, 255);

    }
    else if (code == 826) {
        addStringToBuffer(payload, name, 0, 255);
        addStringToBuffer(payload, key, 0, 160);
    }
    else if (code == 828) {
        addUint32ToBuffer(payload, contectSize);
        addUint32ToBuffer(payload, origFileSize);
        addUint32ToBuffer(payload, packetInfo);
        addStringToBuffer(payload, name, 0, 255);
        addStringToBuffer(payload, name, 1, 0);
    }

    header.payloadSize = static_cast<uint32_t>(payload.size());

    buffers.push_back(boost::asio::buffer(&header, sizeof(header)));
    buffers.push_back(boost::asio::buffer(payload));

    boost::asio::write(socket, buffers);
}

int main()
{
    std::ifstream meFile("me.info");
    std::string line;
    std::vector<std::string> me_info_content;

    // if me.info exists
    if (meFile.is_open()) {

    }
    // if me.info doesnt exists
    else {
        std::ifstream transferFile("transfer.json");
        std::string serverIP;
        std::string port;
        std::string name;
        int line_counter = 1;

        if (transferFile.is_open()) {
            while (std::getline(transferFile, line)) {
                if (line.find("\"ip\"") != std::string::npos) {
                    serverIP = extractStringVal(line);
                }
                else if (line.find("\"port\"") != std::string::npos) {
                    port = extractIntVal(line);
                }
                else if (line.find("\"client\"") != std::string::npos) {
                    name = extractStringVal(line);
                }
            }

            transferFile.close();

            boost::asio::io_context io_context;
            tcp::socket s(io_context);
            tcp::resolver resolver(io_context);

            boost::asio::connect(s, resolver.resolve(serverIP, port));

            sendRequest(s, 825, name);
            
        }
        else {
            std::cerr << "Error: failed to open transfer.json." << std::endl;
        }

    }

    return 0;
}



std::string extractStringVal(std::string& line) {
    int colonPos = line.find(":");

    if (colonPos != std::string::npos) {
        int firstQuotePos = line.find("\"", colonPos);

        if (firstQuotePos != std::string::npos) {
            int secondQuotePos = line.find("\"", firstQuotePos + 1);

            if (secondQuotePos != std::string::npos) {
                return line.substr(firstQuotePos + 1, secondQuotePos - firstQuotePos - 1);
            }
        }
    }

    return "";
}

std::string extractIntVal(std::string& line) {
    int colonPos = line.find(":");

    if (colonPos != std::string::npos) {
        int commaPos = line.find(",", colonPos + 1);

        if (commaPos != std::string::npos) {
            return line.substr(colonPos + 2, commaPos - (colonPos + 2));
        }
    }
    return "";
}

void addStringToBuffer(std::vector<uint8_t>& buffer, const std::string& str, bool dynamic, size_t size) {
    if (dynamic) {
        buffer.insert(buffer.end(), str.begin(), str.end());
    }
    else {
        size_t copySize = std::min(str.size(), size - 1);
        buffer.insert(buffer.end(), str.begin(), str.begin() + copySize);
        size_t nullsSize = size - copySize;
        buffer.insert(buffer.end(), nullsSize, 0);
    }
}

void addUint32ToBuffer(std::vector<uint8_t>& buffer, uint32_t value) {
    buffer.push_back(value & 0xFF);
    buffer.push_back((value >> 8) & 0xFF);
    buffer.push_back((value >> 16) & 0xFF);
    buffer.push_back((value >> 24) & 0xFF);
}