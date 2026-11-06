"""Java / Kotlin / C# / Go / PHP through the C-family frontend."""
from vulnscan.taint import analyze_project


def bl(files, file=None):
    return {f.line: f.rule_id for f in analyze_project(files) if file is None or f.file == file}


def test_java_servlet_command_sql_xss_and_guard():
    src = (
        "package demo;\n"
        "import javax.servlet.http.*;\n"
        "public class RunServlet extends HttpServlet {\n"
        "    protected void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
        "        String cmd = request.getParameter(\"cmd\");\n"
        "        Runtime.getRuntime().exec(\"ls \" + cmd);\n"
        "        conn.prepareStatement(\"SELECT * FROM t WHERE id=\" + request.getParameter(\"id\"));\n"
        "        response.getWriter().write(\"Hello \" + cmd);\n"
        "        if (ALLOWED.contains(cmd)) { Runtime.getRuntime().exec(cmd); }\n"
        "        Runtime.getRuntime().exec(\"ls -la\");\n"
        "    }\n"
        "}\n"
    )
    b = bl({"RunServlet.java": src})
    assert b.get(6) == "DF002" and b.get(7) == "DF004" and b.get(8) == "DF013", b
    assert 9 not in b and 10 not in b, b


def test_kotlin_spring_controller_with_injected_service_across_files():
    ctl = (
        "import org.springframework.web.bind.annotation.*\n"
        "@RestController\n"
        "class RunController(private val shell: Shell) {\n"
        "    @GetMapping(\"/run\")\n"
        "    fun run(@RequestParam q: String): String {\n"
        "        val cmd = \"ls $q\"\n"
        "        Runtime.getRuntime().exec(cmd)\n"
        "        shell.run(q)\n"
        "        return q\n"
        "    }\n"
        "}\n"
    )
    svc = "class Shell {\n    fun run(c: String) { ProcessBuilder(\"sh\", \"-c\", c).start() }\n}\n"
    b = bl({"RunController.kt": ctl, "Shell.kt": svc}, "RunController.kt")
    assert b.get(7) == "DF002", b
    assert b.get(8) == "DF003", b      # typed field (param property) -> other file's method -> ProcessBuilder


def test_csharp_controller_process_sql_reflection():
    src = (
        "using System.Diagnostics;\n"
        "namespace Demo {\n"
        "  [ApiController]\n"
        "  public class RunController : ControllerBase {\n"
        "    [HttpGet(\"run\")]\n"
        "    public IActionResult Run(string cmd) {\n"
        "        var full = $\"ls {cmd}\";\n"
        "        Process.Start(\"cmd.exe\", \"/c \" + full);\n"
        "        var q = Request.Query[\"id\"];\n"
        "        var c = new SqlCommand(\"SELECT * FROM t WHERE id=\" + q, conn);\n"
        "        Response.Write(\"Hello \" + cmd);\n"
        "        return Content(\"ok\");\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    b = bl({"RunController.cs": src})
    assert b.get(8) == "DF002" and b.get(10) == "DF004" and b.get(11) == "DF013", b


def test_go_http_handler_exec_and_reflection():
    src = (
        "package main\n"
        "import (\n    \"net/http\"\n    \"os/exec\"\n    \"fmt\"\n)\n"
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        "    cmd := r.URL.Query().Get(\"cmd\")\n"
        "    exec.Command(\"sh\", \"-c\", cmd).Output()\n"
        "    fmt.Fprintf(w, \"Hello %s\", cmd)\n"
        "    exec.Command(\"ls\", \"-la\").Output()\n"
        "}\n"
    )
    b = bl({"main.go": src})
    assert b.get(9) == "DF003" and b.get(10) == "DF013", b
    assert 11 not in b, b


def test_php_superglobals_functions_and_class_method():
    src = (
        "<?php\n"
        "$cmd = $_GET['cmd'];\n"
        "system(\"ls \" . $cmd);\n"
        "$db->query(\"SELECT * FROM t WHERE id=\" . $_POST['id']);\n"
        "echo \"Hello \" . $cmd;\n"
        "if (in_array($cmd, $allowed)) { shell_exec($cmd); }\n"
        "function run($c) { exec($c); }\n"
        "run($_REQUEST['x']);\n"
        "echo htmlspecialchars($cmd);\n"
        "system(\"ls -la\");\n"
    )
    b = bl({"index.php": src})
    assert b.get(3) == "DF002" and b.get(4) == "DF004" and b.get(5) == "DF013" and b.get(8) == "DF002", b
    assert 6 not in b and 9 not in b and 10 not in b, b
