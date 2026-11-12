// expect-none: DF002
#include <QCoreApplication>
#include <QProcess>
#include <QStringList>

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    QString host = QString::fromLocal8Bit(argv[1]);
    QProcess proc;
    proc.start("uptime", QStringList());
    proc.waitForFinished();
    return host.size();
}
