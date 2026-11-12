class Course:
    @staticmethod
    def create(conn, title):
        conn.execute("INSERT INTO courses (title) VALUES (?)", (title,))
