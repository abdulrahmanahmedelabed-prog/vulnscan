set define off
prompt creating package
create or replace package body orders_pkg as
  procedure search(p_name in varchar2, p_sort in varchar2 default 'id') is
    l_sql   varchar2(4000);
    l_cur   sys_refcursor;
    type t_ids is table of number;
  begin
    l_sql := 'select * from orders where name = ''' || p_name || ''' order by ' || p_sort;
    execute immediate l_sql;
    open l_cur for 'select * from t where c = :1' using p_name;
    open l_cur for select * from orders where name = p_name;
    for r in (select id from orders) loop
      htp.p('<li>' || r.id || '</li>');
    end loop;
  exception
    when no_data_found then null;
    when others then raise;
  end search;

  function safe(p_x in varchar2) return varchar2 is
  begin
    if p_x in ('A','B') then
      return dbms_assert.enquote_literal(p_x);
    elsif p_x is null then
      return null;
    else
      return apex_escape.html(p_x);
    end if;
  end;
end orders_pkg;
/
begin
  orders_pkg.search(p_name => :P10_NAME, p_sort => v('P10_SORT'));
  htp.p(:P10_TITLE);
  htp.p(apex_escape.html(:P10_TITLE));
  :P10_OUT := 'x';
end;
/
