// expect: DF004
#include <pqxx/pqxx>
#include <string>

int main(int argc, char *argv[]) {
    pqxx::connection conn("dbname=shop");
    pqxx::work txn(conn);
    std::string id = argv[1];
    txn.exec0("DELETE FROM carts WHERE id = " + id);
    txn.commit();
    return 0;
}
