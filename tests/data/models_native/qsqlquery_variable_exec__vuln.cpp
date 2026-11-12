// expect: DF004
#include <QSqlQuery>
#include <QString>

int main(int argc, char *argv[]) {
    QString name = QString::fromLocal8Bit(argv[1]);
    QSqlQuery query;
    query.exec("SELECT id FROM accounts WHERE name = '" + name + "'");
    return query.size();
}
