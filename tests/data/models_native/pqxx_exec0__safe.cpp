// expect-none: DF004
#include <pqxx/pqxx>
#include <string>

int main(int argc, char *argv[]) {
    pqxx::connection conn("dbname=shop");
    pqxx::work txn(conn);
    std::string id = argv[1];
    txn.exec_params("DELETE FROM carts WHERE id = $1", id);
    txn.commit();
    return 0;
}
