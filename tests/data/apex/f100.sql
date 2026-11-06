prompt --application/set_environment
set define off verify off feedback off
whenever sqlerror exit sql.sqlcode rollback
begin
wwv_flow_imp.import_begin (
 p_version_yyyy_mm_dd=>'2024.05.31'
,p_release=>'24.1.0'
,p_default_workspace_id=>1234
,p_default_application_id=>100
);
end;
/
prompt --application/pages/page_00010
begin
wwv_flow_imp_page.create_page(
 p_id=>10
,p_name=>'Orders'
,p_step_title=>'Orders'
,p_javascript_code=>wwv_flow_string.join(wwv_flow_t_varchar2(
'var t = "&P10_NAME.";',
'var ok = "&P10_NAME!JS.";'))
);
wwv_flow_imp_page.create_page_plug(
 p_id=>wwv_flow_imp.id(1001)
,p_plug_name=>'Orders Report'
,p_query_type=>'SQL'
,p_plug_source=>wwv_flow_string.join(wwv_flow_t_varchar2(
'select id, name',
'  from orders',
' where name like ''%&P10_SEARCH.%''',
'   and status = :P10_STATUS'))
,p_plug_source_type=>'NATIVE_SQL_REPORT'
);
wwv_flow_imp_page.create_report_columns(
 p_id=>wwv_flow_imp.id(1002)
,p_query_column_id=>2
,p_column_alias=>'NAME'
,p_display_as=>'WITHOUT_MODIFICATION'
);
wwv_flow_imp_page.create_page_plug(
 p_id=>wwv_flow_imp.id(1003)
,p_plug_name=>'Greeting'
,p_plug_source=>wwv_flow_string.join(wwv_flow_t_varchar2(
'begin',
'  htp.p(''<h2>Hello '' || :P10_NAME || ''</h2>'');',
'  htp.p(''<p>'' || apex_escape.html(:P10_NAME) || ''</p>'');',
'end;'))
,p_plug_source_type=>'NATIVE_PLSQL'
);
wwv_flow_imp_page.create_page_process(
 p_id=>wwv_flow_imp.id(1004)
,p_process_sequence=>10
,p_process_type=>'NATIVE_PLSQL'
,p_process_name=>'Search Orders'
,p_process_sql_clob=>wwv_flow_string.join(wwv_flow_t_varchar2(
'declare',
'  l_sql varchar2(4000);',
'begin',
'  orders_pkg.search(p_name => :P10_NAME, p_sort => :P10_SORT);',
'  l_sql := ''delete from orders where id = '' || :P10_ID;',
'  execute immediate l_sql;',
'  execute immediate ''delete from orders where id = :1'' using :P10_ID;',
'end;'))
);
wwv_flow_imp_page.create_page_da_event(
 p_id=>wwv_flow_imp.id(1005)
,p_name=>'Ask Assistant'
,p_triggering_element_type=>'BUTTON'
);
wwv_flow_imp_page.create_page_da_action(
 p_id=>wwv_flow_imp.id(1006)
,p_action=>'NATIVE_EXECUTE_PLSQL_CODE'
,p_attribute_01=>wwv_flow_string.join(wwv_flow_t_varchar2(
'declare',
'  l_sql clob;',
'begin',
'  l_sql := apex_ai.generate(',
'             p_prompt        => ''Write SQL for: '' || :P10_QUESTION,',
'             p_system_prompt => ''You are a helpful SQL assistant for '' || :P10_ROLE);',
'  execute immediate l_sql;',
'  htp.p(apex_ai.generate(p_prompt => :P10_QUESTION));',
'end;'))
,p_attribute_02=>'P10_QUESTION,P10_ROLE'
);
wwv_flow_imp_page.create_page_da_action(
 p_id=>wwv_flow_imp.id(1007)
,p_action=>'NATIVE_JAVASCRIPT_CODE'
,p_attribute_01=>'apex.message.alert("&P10_QUESTION.");'
);
end;
/
prompt --application/shared_components/ai_config
begin
wwv_flow_imp_shared.create_ai_config(
 p_id=>wwv_flow_imp.id(2001)
,p_name=>'Sales Assistant'
,p_static_id=>'sales_assistant'
,p_system_prompt=>'You are a sales assistant. The current customer is &P10_CUSTOMER. Answer only about their orders.'
,p_welcome_message=>'Hello &APP_USER.'
);
end;
/
prompt --application/shared_components/plugins/region_type/greeting
begin
wwv_flow_imp.g_varchar2_table := wwv_flow_imp.empty_varchar2_table;
wwv_flow_imp.g_varchar2_table(1) := '66756E6374696F6E2073686F774E616D65286E297B0A2020646F63756D656E742E676574456C656D656E744279496428226F757422292E696E6E657248544D4C203D206E3B0A7D0A';
wwv_flow_imp_shared.create_plugin_file(
 p_id=>wwv_flow_imp.id(3002)
,p_plugin_id=>wwv_flow_imp.id(3001)
,p_file_name=>'greeting.js'
,p_mime_type=>'text/javascript'
,p_file_content=>wwv_flow_imp.varchar2_to_blob(wwv_flow_imp.g_varchar2_table)
);
wwv_flow_imp_shared.create_plugin(
 p_id=>wwv_flow_imp.id(3001)
,p_plugin_type=>'ITEM TYPE'
,p_name=>'COM.ACME.GREETING'
,p_display_name=>'Greeting'
,p_plsql_code=>wwv_flow_string.join(wwv_flow_t_varchar2(
'procedure render (',
'    p_item   in            apex_plugin.t_item,',
'    p_plugin in            apex_plugin.t_plugin,',
'    p_param  in            apex_plugin.t_item_render_param,',
'    p_result in out nocopy apex_plugin.t_item_render_result )',
'is',
'begin',
'    sys.htp.p(''<span>'' || p_param.value || ''</span>'');',
'    sys.htp.p(''<span>'' || apex_escape.html(p_param.value) || ''</span>'');',
'end render;'))
,p_render_function=>'render'
);
end;
/
