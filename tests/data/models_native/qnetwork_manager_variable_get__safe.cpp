// expect-none: DF010
#include <QNetworkAccessManager>
#include <QTcpSocket>

void forward(QTcpSocket *socket, QNetworkAccessManager *manager) {
    QString line = QString::fromUtf8(socket->readLine()).trimmed();
    manager->get(buildRequest(QStringLiteral("https://updates.example.com/feed")));
    qDebug() << line.size();
}
