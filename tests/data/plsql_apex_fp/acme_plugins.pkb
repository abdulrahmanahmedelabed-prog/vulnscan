create or replace package body acme_plugins as
  -- APEX region plug-in: the renderer package is chosen by the developer in the region attributes
  function render_region (
    p_region              in apex_plugin.t_region,
    p_plugin              in apex_plugin.t_plugin,
    p_is_printer_friendly in boolean )
    return apex_plugin.t_region_render_result
  is
    l_pkg    varchar2(128) := p_region.attribute_01;
    l_result apex_plugin.t_region_render_result;
  begin
    if not regexp_like(l_pkg, '^[A-Za-z][A-Za-z0-9_$#]{0,29}$') then
      raise_application_error(-20001, 'Invalid renderer package');
    end if;
    execute immediate 'begin ' || l_pkg || '.render(p_id => :1, p_filter => :2, p_sort => :3); end;'
      using p_region.static_id, apex_application.g_x01, v('P1_SORT');
    htp.p('<div id="' || apex_escape.html_attribute(p_region.static_id) || '_chart"></div>');
    return l_result;
  end render_region;

  -- AJAX callback: the package name comes from the browser, guarded by an allow-list pattern
  function ajax_region (
    p_region in apex_plugin.t_region,
    p_plugin in apex_plugin.t_plugin )
    return apex_plugin.t_region_ajax_result
  is
    l_pkg    varchar2(128) := apex_application.g_x01;
    l_result apex_plugin.t_region_ajax_result;
  begin
    if not regexp_like(l_pkg, '^[A-Za-z][A-Za-z0-9_$#]{0,29}$') then
      raise_application_error(-20002, 'Invalid package');
    end if;
    execute immediate 'begin ' || l_pkg || '.refresh(:1); end;' using apex_application.g_x02;
    return l_result;
  end ajax_region;

  -- true positive: browser value concatenated without a guard
  procedure ajax_unsafe is
    l_pkg varchar2(128) := apex_application.g_x01;
  begin
    execute immediate 'begin ' || l_pkg || '.refresh; end;';
  end ajax_unsafe;

  -- true positive: an unanchored pattern is not an allow-list
  procedure ajax_unanchored is
    l_pkg varchar2(128) := v('P1_PKG');
  begin
    if not regexp_like(l_pkg, '[A-Za-z]') then
      raise_application_error(-20003, 'Invalid package');
    end if;
    execute immediate 'begin ' || l_pkg || '.refresh; end;';
  end ajax_unanchored;

  -- DBMS_ASSERT, numeric conversion and allow-list stripping are sanitisers; DBMS_ASSERT.NOOP is not
  procedure counts is
    l_n number;
  begin
    execute immediate 'select count(*) from ' || dbms_assert.sql_object_name(v('P1_TABLE')) into l_n;
    execute immediate 'select count(*) from ' || sys.dbms_assert.enquote_name(v('P1_TABLE')) into l_n;
    execute immediate 'select count(*) from t where c = ' || dbms_assert.enquote_literal(v('P1_VALUE')) into l_n;
    execute immediate 'select count(*) from ' || sys.dbms_assert.simple_sql_name(:P1_TABLE) into l_n;
    execute immediate 'select count(*) from t where id = ' || to_number(v('P1_ID')) into l_n;
    execute immediate 'select count(*) from ' || regexp_replace(v('P1_TABLE'), '[^A-Za-z0-9_]', '') into l_n;
    execute immediate 'select count(*) from ' || dbms_assert.noop(v('P1_TABLE')) into l_n;
  end counts;

  -- binds: USING, OPEN … FOR … USING and DBMS_SQL.BIND_VARIABLE never taint the statement text
  procedure binds is
    l_rc  sys_refcursor;
    l_cur integer;
    l_n   integer;
  begin
    open l_rc for 'select * from emp where ename = :n' using v('P1_NAME');
    open l_rc for 'select * from emp where ename = ''' || v('P1_NAME') || '''';
    l_cur := dbms_sql.open_cursor;
    dbms_sql.parse(l_cur, 'select ename from emp where deptno = :d', dbms_sql.native);
    dbms_sql.bind_variable(l_cur, ':d', v('P1_DEPT'));
    l_n := dbms_sql.execute(l_cur);
    dbms_sql.parse(l_cur, 'select ename from emp where ename = ''' || :P1_NAME || '''', dbms_sql.native);
    execute immediate 'update emp set sal = :1 where empno = :2' using :P1_SAL, :P1_EMPNO;
  end binds;

  -- HTTP headers: htp.p between owa_util.mime_header(…, false) and owa_util.http_header_close writes headers
  procedure download is
    l_name varchar2(200) := v('P1_FILE');
  begin
    owa_util.mime_header('text/csv', false);
    htp.p('Content-Disposition: attachment; filename="' || regexp_replace(l_name, '[^A-Za-z0-9]', '') || '.csv"');
    owa_util.http_header_close;
    htp.p('id,name');
  end download;

  procedure download_unsafe is
  begin
    owa_util.mime_header(ccontent_type => 'text/csv', bclose_header => false);
    htp.p('Content-Disposition: attachment; filename=' || v('P1_FILE'));
    owa_util.http_header_close;
    htp.p('<p>' || v('P1_FILE') || '</p>');
  end download_unsafe;

  procedure greet is
  begin
    htp.p('<h1>Hello ' || apex_application.g_x03 || '</h1>');
    htp.p('<h2>' || regexp_replace(:P1_NAME, '[^A-Za-z0-9]') || '</h2>');
  end greet;
end acme_plugins;
/
