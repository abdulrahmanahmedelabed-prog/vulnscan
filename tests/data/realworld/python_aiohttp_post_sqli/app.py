from aiohttp import web


class Student:
    @staticmethod
    async def create(conn, name):
        q = "INSERT INTO students (name) VALUES ('%(name)s')" % {"name": name}
        async with conn.cursor() as cur:
            await cur.execute(q)


class Course:
    @staticmethod
    async def create(conn, title, description):
        q = "INSERT INTO courses (title, description) VALUES (%(title)s, %(description)s)"
        async with conn.cursor() as cur:
            await cur.execute(q, {"title": title, "description": description})


async def students(request: web.Request):
    data = await request.post()
    async with request.app["db"].acquire() as conn:
        await Student.create(conn, data["name"])
    return web.Response(text="ok")


async def courses(request: web.Request):
    data = await request.post()
    async with request.app["db"].acquire() as conn:
        await Course.create(conn, data["title"], data["description"])
    return web.Response(text="ok")


def init():
    app = web.Application()
    app.router.add_post("/students", students)
    app.router.add_post("/courses", courses)
    return app
