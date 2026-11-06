prompt --application/create_application
begin
wwv_flow_imp.create_flow(
 p_id=>wwv_flow.g_flow_id
,p_name=>'HR Portal'
,p_page_protection_enabled_y_n=>'N'
,p_bookmark_checksum_function=>'MD5'
,p_authentication_id=>wwv_flow_imp.id(9001)
,p_flow_status=>'AVAILABLE_W_EDIT_LINK'
,p_exact_substitutions_only=>'N'
,p_browser_frame=>'A'
,p_rejoin_existing_sessions=>'Y'
,p_html_escaping_mode=>'B'
,p_runtime_api_usage=>'T:O:W'
);
end;
/
begin
wwv_flow_imp_shared.create_authentication(
 p_id=>wwv_flow_imp.id(9001)
,p_name=>'Custom Auth'
,p_scheme_type=>'NATIVE_CUSTOM'
,p_use_secure_cookie_yn=>'N'
,p_plsql_code=>wwv_flow_string.join(wwv_flow_t_varchar2(
'function my_auth(p_username in varchar2, p_password in varchar2) return boolean is',
'  l number;',
'begin',
'  select count(*) into l from app_users where username = upper(p_username) and password = p_password;',
'  return l = 1;',
'end;'))
);
wwv_flow_imp_shared.create_flow_process(
 p_id=>wwv_flow_imp.id(9002)
,p_process_sequence=>1
,p_process_point=>'ON_DEMAND'
,p_process_type=>'NATIVE_PLSQL'
,p_process_name=>'GET_SALARY'
,p_process_sql_clob=>'htp.p(1);'
);
end;
/
prompt --application/pages/page_00010
begin
wwv_flow_imp_page.create_page(
 p_id=>10
,p_name=>'Salaries'
,p_page_is_public_y_n=>'N'
,p_protection_level=>'U'
);
wwv_flow_imp_page.create_page_item(
 p_id=>wwv_flow_imp.id(9010)
,p_name=>'P10_EMP_ID'
,p_display_as=>'NATIVE_HIDDEN'
,p_attribute_01=>'N'
);
wwv_flow_imp_page.create_page_process(
 p_id=>wwv_flow_imp.id(9011)
,p_process_sequence=>10
,p_process_point=>'AFTER_SUBMIT'
,p_process_type=>'NATIVE_PLSQL'
,p_process_name=>'Raise Salary'
,p_process_sql_clob=>'update emp set sal = sal * 2 where empno = :P10_EMP_ID;'
);
end;
/
prompt --application/pages/page_00020
begin
wwv_flow_imp_page.create_page(
 p_id=>20
,p_name=>'Contact Us'
,p_page_is_public_y_n=>'Y'
,p_protection_level=>'C'
);
wwv_flow_imp_page.create_page_process(
 p_id=>wwv_flow_imp.id(9020)
,p_process_sequence=>10
,p_process_point=>'AFTER_SUBMIT'
,p_process_type=>'NATIVE_PLSQL'
,p_process_name=>'Save Message'
,p_process_sql_clob=>'insert into messages (body) values (:P20_BODY);'
);
end;
/
prompt --application/pages/page_09999
begin
wwv_flow_imp_page.create_page(
 p_id=>9999
,p_name=>'Login Page'
,p_page_is_public_y_n=>'Y'
,p_protection_level=>'U'
);
wwv_flow_imp_page.create_page_process(
 p_id=>wwv_flow_imp.id(9991)
,p_process_sequence=>10
,p_process_point=>'AFTER_SUBMIT'
,p_process_type=>'NATIVE_PLSQL'
,p_process_name=>'Login'
,p_process_sql_clob=>'apex_authentication.login(p_username => :P9999_USERNAME, p_password => :P9999_PASSWORD);'
);
end;
/
