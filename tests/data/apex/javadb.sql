create or replace and compile java source named "Shell" as
public class Shell {
    public static String run(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd);
        return "ok";
    }
}
/
create or replace function run_os(p_cmd in varchar2) return varchar2
as language java name 'Shell.run(java.lang.String) return java.lang.String';
/
create or replace procedure admin_tool is
  l_out varchar2(100);
begin
  l_out := run_os('ls ' || :P20_PATH);
end;
/
