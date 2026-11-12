class Student:
    @staticmethod
    def create(conn, name):
        conn.execute("INSERT INTO students (name) VALUES ('%s')" % name)
