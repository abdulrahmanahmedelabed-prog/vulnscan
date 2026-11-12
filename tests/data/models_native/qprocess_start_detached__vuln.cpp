// expect: DF002
#include <QProcess>
#include <QString>

int main(int argc, char *argv[]) {
    QString viewer = QString::fromLocal8Bit(argv[1]);
    QProcess::startDetached(viewer);
    return 0;
}
