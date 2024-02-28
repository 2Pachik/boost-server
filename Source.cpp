#define _CRT_SECURE_NO_WARNINGS
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING
#define BOOST_EXCEPTION_DISABLE
#define BOOST_NO_EXCEPTION
#define WIN32_LEAN_AND_MEAN

#include "usage_headers/base64.h"
#include "usage_headers/md5.h"
#include "usage_headers/hmac.hpp"
#include <boost/format.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/beast.hpp>
#include <boost/config.hpp>
#include <boost/thread.hpp>
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

int getFileSize(const std::string& path) {

    std::ifstream file(path, std::ios::binary);

    if (file.is_open()) {
        file.seekg(0, std::ios::end);
        int size = file.tellg();
        file.close();
        return size;
    }

    else {
        return -1;
    }
}

void getFileData(const std::string& path, char* buff) {

    std::shared_ptr<FILE*> file = std::make_shared<FILE*>();
    int size = getFileSize(path);

    if (*file.get() = fopen(path.data(), "rb")) {
        fread(buff, 1, size, *file.get());
        fclose(*file.get());
    }
}

std::string localPath() {

    WCHAR filename[MAX_PATH];
    DWORD fname = GetModuleFileNameW(NULL, filename, MAX_PATH);

    std::wstring wpath = filename;
    std::string filepath(wpath.begin(), wpath.end());

    boost::format fmt("%1%|");
    filepath = (fmt % filepath).str();
    int endP = wpath.find_last_of('\\');
    filepath = filepath.substr(0, endP);
    return filepath;
}

std::string getDerictories() {

    boost::format fmt("%1%\\%2%");

    fmt % localPath() % "Server Files";

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

void standartResponse(const boost::beast::http::request <boost::beast::http::string_body>& request, boost::beast::http::status status, const std::string& body , boost::asio::ip::tcp::socket& socket) {

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

    std::cout << std::this_thread::get_id() << std::endl; 

    boost::system::error_code ec;

    std::string md5CheckStr = getAuthData(); // fix

    std::string serverToken;

    for (bool exitFlag = false; exitFlag != true;) {

        boost::beast::flat_buffer buffer;
        boost::beast::http::request <boost::beast::http::string_body> request;
        boost::beast::http::read(*socket.get(), buffer, request, ec);

        std::cout << request << std::endl;

        if (!ec) {

            if (request.target() == "/Auth") {

                try {

                    boost::property_tree::ptree pt;

                    std::istringstream iss(request.body());

                    boost::property_tree::json_parser::read_json(iss, pt);

                    if (pt.get<std::string>("Content-MD5") == md5CheckStr) {

                        std::string jwt = generateJWT("key", "Admin", "12345");

                        serverToken = jwt;

                        boost::format fmtAuth("{\"Authorization\": \"%1%\"}");

                        fmtAuth% jwt;

                        standartResponse(request, boost::beast::http::status::ok, fmtAuth.str(), *socket.get());
                    }

                    else {
                        standartResponse(request, boost::beast::http::status::bad_request, "", *socket.get());
                    }
                }

                catch (std::exception& e) {
                    std::cout << e.what() << std::endl;
                }
            }

            else if (request.target() == "/Directories") {

                try {

                    bool authStatus = checkAuth(request, serverToken);

                    if (authStatus == true) {

                        std::string dirs = getDerictories();

                        boost::format fmtDirs("{\"Directories\": \"%1%\"}");
                        fmtDirs% dirs;

                        standartResponse(request, boost::beast::http::status::ok, fmtDirs.str(), *socket.get());
                    }

                    else {
                        standartResponse(request, boost::beast::http::status::unauthorized, "", *socket.get());
                    }
                }

                catch (std::exception& e) {
                    std::cout << e.what() << std::endl;
                }

                /*catch (boost::exception& e) {
                    std::cout << boost::diagnostic_information(e) << std::endl;
                }*/
            }

            else if (request.target() == "/Download") {
                
                try {

                    bool authStatus = checkAuth(request, serverToken);

                    if (authStatus == true) {

                        boost::property_tree::ptree pt;
                        std::stringstream iss(request.body());
                        boost::property_tree::json_parser::read_json(iss, pt);

                        std::string file = pt.get<std::string>("Path");

                        int size = 0;

                        size = getFileSize(file);

                        /*boost::format fmtSize("{\"Size\": \"%1%\"}");

                        fmtSize% size;*/

                        //standartResponse(request, boost::beast::http::status::ok, fmtSize.str(), *socket.get());

                        if (size != -1) {

                            boost::system::error_code ecReq;

                            /*std::shared_ptr<char[]> data(new char[size]);
                            getFileData(file, data.get());*/

                            boost::beast::http::response<boost::beast::http::file_body> response;
                            response.version(request.version());
                            response.result(boost::beast::http::status::ok);
                            response.set(boost::beast::http::field::server, "HTTP Server");
                            //response.set(boost::beast::http::field::content_type, "audio/wav");
                            response.body().open(file.c_str(), boost::beast::file_mode::scan, ecReq); // = std::move(data.get());
                            response.prepare_payload();
                            boost::beast::http::write(*socket.get(), response);

                            /*boost::format fmtData("{\"Size\": \"%1%\", \"Data\": \"%2%\"}");
                            fmtData% size% B64Encode(data.get());

                            standartResponse(request, boost::beast::http::status::ok, std::move(fmtData.str().data()), *socket.get());*/

                            //socket.get()->send(boost::asio::buffer(data.get(), size), 0, ec);
                        }

                        else {
                            standartResponse(request, boost::beast::http::status::no_content, "", *socket.get());
                        }

                    }

                    else {
                        standartResponse(request, boost::beast::http::status::unauthorized, "", *socket.get());
                    }
                }

                catch (std::exception& e) {
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

    std::string remoteEndp = socket.get()->remote_endpoint().address().to_string();
    socket.get()->close();
    std::cout << "Socket " + remoteEndp + " closed!" << std::endl << std::endl;
}

int main() {

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), 8080);

    int coresCount = std::thread::hardware_concurrency();

    boost::asio::thread_pool tp(coresCount);
    
    while (true) {

        boost::asio::ip::tcp::acceptor acceptor(io_context, ep);
        boost::system::error_code ec;

        std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context);

        acceptor.accept(*socket.get(), ec);
        acceptor.close();

        try {
            boost::asio::post(tp, std::bind(clientHandle, std::move(socket)));
        }
        catch (std::exception& e) {
            std::cout << e.what() << std::endl;
        }
    }

    /*while (true) {    
        
        boost::asio::ip::tcp::acceptor acceptor(io_context, ep);
        boost::system::error_code ec;

        std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context);

        acceptor.accept(*socket.get(), ec);
        
        acceptor.close();

        try {
            std::thread th(clientHandle, std::move(socket));
            th.detach();
        }
        
        catch (...) {
            std::cout << "New thread not started" << std::endl;
        }
    }*/

    return 0;
}