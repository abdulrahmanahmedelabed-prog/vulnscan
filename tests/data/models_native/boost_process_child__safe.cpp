// expect-none: DF002
#include <boost/process.hpp>
#include <string>

int main(int argc, char *argv[]) {
    std::string image = argv[1];
    boost::process::child worker("convert in.png -resize 64x64 thumb.png");
    worker.wait();
    return worker.exit_code() + static_cast<int>(image.size());
}
