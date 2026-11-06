begin
  ords.define_module(
    p_module_name    => 'hr.v1',
    p_base_path      => '/hr/v1/',
    p_items_per_page => 25);

  ords.define_template(
    p_module_name => 'hr.v1',
    p_pattern     => 'employees/:id');

  ords.define_handler(
    p_module_name    => 'hr.v1',
    p_pattern        => 'employees/:id',
    p_method         => 'GET',
    p_source_type    => ords.source_type_collection_item,
    p_source         => q'[select * from emp where empno = :id and hr_util.visible(:id) = 1]');

  ords.define_handler(
    p_module_name    => 'hr.v1',
    p_pattern        => 'employees/search',
    p_method         => 'POST',
    p_source_type    => ords.source_type_plsql,
    p_source         => q'[
declare
  l_sql varchar2(4000);
begin
  l_sql := 'select * from emp where ename = ''' || :name || '''';
  open :result for l_sql;
  :forward_location := :next_url;
end;]');
  commit;
end;
/
create or replace package body hr_util as
  function visible(p_id in varchar2) return number is
    l number;
  begin
    execute immediate 'select count(*) from emp where empno = ' || p_id into l;
    return l;
  end;
end hr_util;
/
