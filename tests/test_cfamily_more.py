"""C/C++, Rust, Swift and Ruby through the C-family frontend (data flow + parse diagnostics)."""
from vulnscan.taint import analyze_project
from vulnscan.cfamily_frontend import parse_cfamily_ex


def bl(files, file=None):
    return {f.line: f.rule_id for f in analyze_project(files) if file is None or f.file == file}


def diag(text, rel, lang):
    return parse_cfamily_ex(text, rel, lang)[1]


def test_cpp_method_field_flow_and_unsafe_apis():
    src = (
        "#include <cstdlib>\n"
        "#include <string>\n"
        "using namespace std;\n"
        "class Runner {\n"
        "public:\n"
        "  Runner(std::string base) : base_(base) {}\n"
        "  void run(const std::string& cmd);\n"
        "private:\n"
        "  std::string base_;\n"
        "};\n"
        "void Runner::run(const std::string& cmd) {\n"
        "  std::string full = base_ + \" \" + cmd;\n"
        "  system(full.c_str());\n"
        "}\n"
        "int main(int argc, char** argv) {\n"
        "  char buf[256];\n"
        "  strcpy(buf, argv[1]);\n"
        "  printf(argv[1]);\n"
        "  Runner r(\"ls\");\n"
        "  r.run(argv[1]);\n"
        "}\n"
    )
    b = bl({"main.cpp": src})
    assert b.get(17) == "DF017", b       # strcpy with argv
    assert b.get(18) == "DF018", b       # printf(argv[1]) format string
    assert b.get(20) == "DF002", b       # argv -> r.run -> system via the base_ field (out-of-class method)


def test_rust_impl_assoc_fn_and_actix_route():
    src = (
        "use std::process::Command;\n"
        "use actix_web::{get, web, HttpResponse, Responder};\n"
        "struct Shell { prefix: String }\n"
        "impl Shell {\n"
        "    fn new(prefix: &str) -> Self { Shell { prefix: prefix.to_string() } }\n"
        "    fn run(&self, c: &str) {\n"
        "        let full = format!(\"{} {}\", self.prefix, c);\n"
        "        Command::new(\"sh\").arg(\"-c\").arg(full).output().unwrap();\n"
        "    }\n"
        "}\n"
        "#[get(\"/run\")]\n"
        "async fn run(q: web::Query<Params>) -> impl Responder {\n"
        "    let cmd = q.cmd.clone();\n"
        "    let shell = Shell::new(\"ls\");\n"
        "    shell.run(&cmd);\n"
        "    HttpResponse::Ok().body(format!(\"ran {cmd}\"))\n"
        "}\n"
    )
    b = bl({"main.rs": src})
    assert b.get(15) == "DF002", b       # query -> Shell::run -> Command (associated fn keeps no receiver)
    assert b.get(16) == "DF013", b       # reflected into the response body


def test_swift_vapor_closure_route_and_process():
    src = (
        "import Vapor\n"
        "final class Shell {\n"
        "    let prefix: String\n"
        "    init(prefix: String) { self.prefix = prefix }\n"
        "    func run(_ cmd: String) {\n"
        "        let task = Process()\n"
        "        task.launchPath = \"/bin/sh\"\n"
        "        task.arguments = [\"-c\", \"\\(prefix) \\(cmd)\"]\n"
        "        try? task.run()\n"
        "    }\n"
        "}\n"
        "func routes(_ app: Application) throws {\n"
        "    app.get(\"run\") { req -> String in\n"
        "        let cmd = req.query[String.self, at: \"cmd\"] ?? \"\"\n"
        "        Shell(prefix: \"ls\").run(cmd)\n"
        "        return \"ok \\(cmd)\"\n"
        "    }\n"
        "}\n"
    )
    b = bl({"App.swift": src})
    assert b.get(15) == "DF002", b       # cmd -> Shell.run -> Process.arguments (attr sink), reported at the call
    assert b.get(16) == "DF013", b       # reflected into the returned response


def test_ruby_rails_controller_and_sinatra_block():
    src = (
        "class RunController < ApplicationController\n"
        "  def run\n"
        "    cmd = params[:cmd]\n"
        "    system(\"ls #{cmd}\")\n"
        "    User.where(\"name = '#{params[:name]}'\")\n"
        "    render plain: cmd\n"
        "  end\n"
        "end\n"
        "get '/x' do\n"
        "  exec params[:y]\n"
        "end\n"
    )
    b = bl({"app.rb": src})
    assert b.get(4) == "DF002", b        # command injection in interpolated system()
    assert b.get(5) == "DF004", b        # SQL injection in where
    assert b.get(10) == "DF002", b       # exec in a Sinatra route block (entry point)


def test_ruby_method_object_flow_across_classes():
    src = (
        "class Shell\n"
        "  def initialize(prefix)\n"
        "    @prefix = prefix\n"
        "  end\n"
        "  def run(cmd)\n"
        "    system(\"#{@prefix} #{cmd}\")\n"
        "  end\n"
        "end\n"
        "class C < ApplicationController\n"
        "  def run\n"
        "    Shell.new(\"ls\").run(params[:cmd])\n"
        "  end\n"
        "end\n"
    )
    assert bl({"app.rb": src}).get(11) == "DF002"


def test_unparseable_statements_are_reported_not_dropped():
    # A deliberately broken line is skipped and recorded; the rest still parses and flows.
    src = (
        "fn f(req: Request) {\n"
        "    let x = = = 5;\n"
        "    let cmd = req.cmd;\n"
        "    std::process::Command::new(cmd);\n"
        "}\n"
    )
    d = diag(src, "x.rs", "rust")
    assert d["skipped"] >= 1 and d["statements"] >= 1
    assert any(ln == 2 for ln, _ in d["lines"])
    assert bl({"x.rs": src}).get(4) == "DF002"   # recovery: the sink after the bad line is still found
