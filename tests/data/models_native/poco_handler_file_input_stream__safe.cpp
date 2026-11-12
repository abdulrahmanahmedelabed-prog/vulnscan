// expect-none: DF005
#include <Poco/FileStream.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/StreamCopier.h>

class StaticHandler : public Poco::Net::HTTPRequestHandler {
public:
    void handleRequest(Poco::Net::HTTPServerRequest &request, Poco::Net::HTTPServerResponse &response) {
        Poco::FileInputStream in("/srv/www/index.html");
        Poco::StreamCopier::copyStream(in, response.send());
    }
};
