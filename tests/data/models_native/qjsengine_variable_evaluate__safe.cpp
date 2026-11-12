// expect-none: DF012
#include <QJSEngine>
#include <QTcpSocket>

void run(QTcpSocket *socket) {
    QJSEngine engine;
    QString program = QString::fromUtf8(socket->readAll());
    engine.globalObject().setProperty("payload", program);
    engine.evaluate("payload.length");
}
