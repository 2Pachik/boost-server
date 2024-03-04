#define _CRT_SECURE_NO_WARNINGS
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING
#define BOOST_EXCEPTION_DISABLE
#define BOOST_NO_EXCEPTION
#define BOOST_ASIO_NO_EXCEPTIONS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX 

#include "usage_headers/base64.h"
#include "usage_headers/md5.h"
#include "usage_headers/hmac.hpp"
#include <boost/format.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/beast.hpp>
#include <boost/config.hpp>
#include <boost/thread.hpp>
#include <boost/regex.hpp>
#include <boost/throw_exception.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <Windows.h>
#include <experimental/filesystem> 
#include <filesystem> 
#include <algorithm> 
#include <cstdint>
#include <fstream>
#include <chrono>
#include <ctime>
#include <stdexcept>

bool checkFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        file.close();
        return false;
    }
    file.close();
    return true;
}

//void getFileData(std::string path, std::byte* buff) {
//
//    std::shared_ptr<FILE*> file = std::make_shared<FILE*>();
//    size_t size = getFileSize(path);
//
//    if (*file.get() = fopen(path.data(), "rb")) {
//        fread(buff, 1, size, *file.get());
//        fclose(*file.get());
//    }
//}

std::string localPath() {
    WCHAR filename[MAX_PATH];
    GetModuleFileNameW(NULL, filename, MAX_PATH);
    std::wstring wpath = filename;
    std::string filepath(wpath.begin(), wpath.end());
    int endP = filepath.find_last_of('\\');
    filepath = filepath.substr(0, endP);
    return filepath;
}

std::string getDerictories() {

    boost::format fmt("%1%\\%2%");

    fmt% localPath() % "Server Files";

    std::string filepath = fmt.str();

    boost::format fmt_("%1%|");

    std::string result;

    for (auto p : std::experimental::filesystem::recursive_directory_iterator(filepath)) {
        result += (fmt_ % p.path().string()).str();
    }

    return result;
}

std::string B64Encode(const std::string& data) {

    std::shared_ptr<unsigned char[]> char_array(new unsigned char[data.length()]);
    for (int i = 0; i < data.length(); i++) {
        char_array.get()[i] = data[i];
    }
    std::string headerstr = Base64Encode(char_array.get(), data.length());
    return headerstr;
}

std::string B64Decode(const std::string& data) {

    std::string headerstr = Base64Decode(data);

    return headerstr;
}

std::string MD5Encode(const std::string& data) {

    MD5 md5;

    return md5(data);
}

std::string generateJWT(std::string key, std::string ulogin, std::string upassword) {

    auto currentTime = std::chrono::system_clock::now();

    auto oneHourLater = currentTime + std::chrono::hours(1);

    auto iat = std::chrono::duration_cast<std::chrono::seconds>(currentTime.time_since_epoch()).count();
    auto exp = std::chrono::duration_cast<std::chrono::seconds>(oneHourLater.time_since_epoch()).count();

    boost::format fheader("{\"alg\": \"HS512\", \"typ\": \"JWT\"}");
    boost::format fpayload("{\"login\": \"%1%\", \"password\": \"%2%\", \"iat\": \"%3%\", \"exp\": \"%4%\"}");

    fpayload% ulogin% upassword% iat% exp;

    std::string header = fheader.str();
    std::string payload = fpayload.str();

    boost::format fmtInput("%1%.%2%");

    fmtInput% B64Encode(header) % B64Encode(payload);

    std::string input = fmtInput.str();

    std::string signature = hmac::get_hmac(key, input, hmac::TypeHash::SHA512);

    boost::format fmtJWT("%1%.%2%.%3%");

    fmtJWT% B64Encode(header) % B64Encode(payload) % B64Encode(signature);

    std::string jwt = fmtJWT.str();

    return jwt;
}

std::string getAuthData() {

    std::string authLogin = std::getenv("LOCAL_SERVER_AUTH_LOGIN");
    std::string authPassword = std::getenv("LOCAL_SERVER_AUTH_PASSWORD");

    boost::format fmt("%1%|%2%");
    fmt% authLogin% authPassword;
    std::string hash = MD5Encode(fmt.str());

    return hash;
}

void standartResponse(const boost::beast::http::request <boost::beast::http::string_body>& request, boost::beast::http::status status, const std::string& body, boost::asio::ip::tcp::socket& socket) {

    boost::beast::http::response<boost::beast::http::string_body> response;
    response.version(request.version());
    response.result(status);
    response.set(boost::beast::http::field::server, "HTTP Server");
    response.set(boost::beast::http::field::content_type, "application/json");
    response.body() = body;
    response.prepare_payload();
    boost::beast::http::write(socket, response);
}

bool checkAuth(const boost::beast::http::request <boost::beast::http::string_body>& request, const std::string& serverToken)
{
    boost::property_tree::ptree pt;

    std::istringstream iss(request.body());

    boost::property_tree::json_parser::read_json(iss, pt);

    std::string clientToken = pt.get<std::string>("Authorization");

    std::string clientSignature;
    std::string serverSignature;

    clientSignature = pt.get<std::string>("Authorization").substr(clientToken.find_last_of('.') + 1, clientToken.length());

    serverSignature = serverToken.substr(serverToken.find_last_of('.') + 1, serverToken.length());

    if (clientSignature == serverSignature) {

        std::string clientPayload;

        clientPayload = pt.get<std::string>("Authorization").substr(clientToken.find_first_of(".") + 1, clientToken.find_last_of(".") - 1);

        clientPayload = B64Decode(clientPayload);

        boost::property_tree::ptree pt_;

        std::istringstream json_iss(clientPayload);
        boost::property_tree::read_json(json_iss, pt_);

        auto exp = pt_.get<time_t>("exp");

        auto currentTime = std::chrono::system_clock::now();

        auto timePoint = std::chrono::system_clock::from_time_t(exp);

        if (currentTime <= timePoint)
        {
            return true;
        }

        else
        {
            return false;
        }
    }

    else
    {
        return false;
    }
}

void clientHandle(std::shared_ptr<boost::asio::ip::tcp::socket> socket) {

    boost::system::error_code ec;
    std::string md5CheckStr = getAuthData();
    std::string remoteEndp = socket.get()->remote_endpoint().address().to_string();
    std::string serverToken;

    for (bool exitFlag = false; exitFlag != true;) {

        boost::beast::flat_buffer buffer;
        boost::beast::http::request <boost::beast::http::string_body> request;
        boost::beast::http::read(*socket.get(), buffer, request, ec);
        std::cout << remoteEndp << " - " << request.target() << std::endl;

        if (!ec) {
            if (request.target() == "/Auth") {
                try {
                    boost::property_tree::ptree pt;
                    std::stringstream ss(request.body());
                    boost::property_tree::json_parser::read_json(ss, pt);

                    if (pt.get<std::string>("Content-MD5") == md5CheckStr) {

                        std::string jwt = generateJWT("key", "Admin", "12345");
                        serverToken = jwt;
                        boost::property_tree::ptree pt_;
                        pt_.put("Authorization", jwt);
                        std::stringstream responseBody;
                        boost::property_tree::json_parser::write_json(responseBody, pt_);
                        standartResponse(request, boost::beast::http::status::ok, responseBody.str(), *socket.get());
                    }
                    else {
                        standartResponse(request, boost::beast::http::status::bad_request, "", *socket.get());
                    }
                }
                catch (std::exception& e) {
                    std::cout << e.what() << std::endl;
                }
                catch (boost::system::system_error& e) {
                    std::cout << e.what() << std::endl;
                }
            }
            else if (request.target() == "/Directories") {
                try {
                    bool authStatus = checkAuth(request, serverToken);

                    if (authStatus == true) {
                        std::string dirs = getDerictories();
                        boost::property_tree::ptree pt_;
                        pt_.put("Directories", dirs);
                        std::stringstream responseBody;
                        boost::property_tree::json_parser::write_json(responseBody, pt_);
                        standartResponse(request, boost::beast::http::status::ok, responseBody.str(), *socket.get());
                    }
                    else {
                        standartResponse(request, boost::beast::http::status::unauthorized, "", *socket.get());
                    }
                }
                catch (std::exception& e) {
                    std::cout << e.what() << std::endl;
                }
                catch (boost::system::system_error& e) {
                    std::cout << e.what() << std::endl;
                }
            }
            else if (request.target() == "/Download") {
                try {
                    bool auth = checkAuth(request, serverToken);
                    if (auth == true) {
                        boost::property_tree::ptree pt;
                        std::istringstream ss(request.body());
                        boost::property_tree::json_parser::read_json(ss, pt);
                        std::string filePath = pt.get<std::string>("Path");

                        //if (checkFile(filePath) == true) {
                            boost::system::error_code ecReq;
                            boost::beast::http::response_parser<boost::beast::http::file_body> res_parser;
                            res_parser.body_limit((std::numeric_limits<std::uint64_t>::max)());
                            res_parser.get().version(request.version());
                            res_parser.get().set(boost::beast::http::field::server, "HTTP Server");
                            res_parser.get().body().open(filePath.c_str(), boost::beast::file_mode::scan, ecReq);
                            res_parser.get().prepare_payload();
                            boost::beast::http::write(*socket.get(), res_parser.get(), ecReq);

                            std::cerr << ecReq.what() << std::endl;
                        //}

                        //else {
                        //    standartResponse(request, boost::beast::http::status::not_found, "", *socket.get());
                        //}
                    }

                    else {
                        standartResponse(request, boost::beast::http::status::unauthorized, "", *socket.get());
                    }
                }
                catch (std::exception& e) {
                    std::cout << e.what() << std::endl;
                }
                catch (boost::system::system_error& e) {
                    std::cout << e.what() << std::endl;
                }
            }
            else
            {
                standartResponse(request, boost::beast::http::status::bad_request, "", *socket.get());
            }
        }
        else {
            exitFlag = true;
            std::cout << ec.what() << std::endl;
        }

    }

    socket.get()->close();
    std::cout << "Socket " + remoteEndp + " closed!" << std::endl << std::endl;
}

bool checkArguments(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: program <ip> <port>\n";
        return false;
    }

    std::string ip(argv[1]);
    std::string port(argv[2]);

    boost::regex ip_regex("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
        "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

    if (boost::regex_match(ip, ip_regex) == false) {
        std::cout << "Invalid IP" << std::endl;
        return false;
    }

    try {
        int portNum = std::stoi(port);
        if (portNum < 1 || portNum > 65535) {
            throw std::out_of_range("Port number out of range");
            return false;
        }
        else {
            return true;
        }
    }
    catch (std::exception& e) {
        std::cout << e.what();
        return false;
    }
    catch (boost::system::system_error& e) {
        std::cout << e.what() << std::endl;
        return false;
    }
}

int main(int argc, char* argv[]) {

    bool argumentsStatus = false;
    argumentsStatus = checkArguments(argc, argv);

    if (argumentsStatus == true) {
        std::cout << "Server started at " << argv[1] << ":" << argv[2] << std::endl;
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::endpoint ep(boost::asio::ip::address::from_string(argv[1]), std::stoi(argv[2]));
        int coresCount = std::thread::hardware_concurrency();
        boost::asio::thread_pool tp(coresCount);

        while (true) {
            try {
                io_context.run();
                boost::asio::ip::tcp::acceptor acceptor(io_context, ep);
                boost::system::error_code ec;
                std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
                acceptor.accept(*socket.get(), ec);
                acceptor.close();
                boost::asio::post(tp, std::bind(clientHandle, std::move(socket)));
            }
            catch (std::exception& e) {
                std::cerr << e.what() << std::endl;
            }
            catch (boost::system::system_error& e) {
                std::cerr << e.what() << std::endl;
            }
        }
    }

    return 0;
}