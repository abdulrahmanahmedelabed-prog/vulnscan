// expect-none: DF002
#include <QProcess>
#include <QString>

int main(int argc, char *argv[]) {
    QString viewer = QString::fromLocal8Bit(argv[1]);
    QProcess::startDetached("/usr/bin/xdg-open", QStringList() << "/usr/share/doc/app/index.html");
    return viewer.size();
}
