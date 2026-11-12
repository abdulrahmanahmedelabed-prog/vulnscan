// expect-none: DF004
#include <QSqlQuery>
#include <QString>

int main(int argc, char *argv[]) {
    QString name = QString::fromLocal8Bit(argv[1]);
    QSqlQuery query;
    query.prepare("SELECT id FROM accounts WHERE name = :name");
    query.bindValue(":name", name);
    query.exec();
    return query.size();
}
