import sqlite3


def get_sync(conn, id_):
    cur = conn.cursor()
    cur.execute("SELECT id FROM students WHERE id = %s", (id_,))


async def get_async(conn, id_):
    async with conn.cursor() as cur:
        await cur.execute("SELECT id FROM students WHERE id = %s", (id_,))


async def get_async_named(conn, name):
    async with conn.cursor() as cur:
        await cur.execute("SELECT id FROM students WHERE name = %(name)s", {"name": name})


def get_vuln(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT id FROM students WHERE name = '%s'" % name)   # true positive
