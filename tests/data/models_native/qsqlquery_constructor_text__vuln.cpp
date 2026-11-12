// expect: DF004
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QString>

int main(int argc, char *argv[]) {
    QSqlDatabase db = QSqlDatabase::database();
    QString id = QString::fromLocal8Bit(argv[1]);
    QSqlQuery purge("DELETE FROM sessions WHERE id = " + id, db);
    return purge.numRowsAffected();
}
