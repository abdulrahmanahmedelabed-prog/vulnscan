// expect-none: DF004
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QString>

int main(int argc, char *argv[]) {
    QSqlDatabase db = QSqlDatabase::database();
    QString id = QString::fromLocal8Bit(argv[1]);
    QSqlQuery purge("DELETE FROM sessions WHERE expired = 1", db);
    return purge.numRowsAffected() + id.size();
}
