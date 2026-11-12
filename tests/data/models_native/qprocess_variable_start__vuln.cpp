// expect: DF002
#include <QCoreApplication>
#include <QProcess>
#include <QStringList>

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    QString host = QString::fromLocal8Bit(argv[1]);
    QProcess proc;
    proc.start("sh", QStringList() << "-c" << "ping -c 1 " + host);
    proc.waitForFinished();
    return 0;
}
