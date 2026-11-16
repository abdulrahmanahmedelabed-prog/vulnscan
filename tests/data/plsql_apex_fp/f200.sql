prompt --application/set_environment
set define off verify off feedback off
whenever sqlerror exit sql.sqlcode rollback
begin
wwv_flow_imp.import_begin (
 p_version_yyyy_mm_dd=>'2024.05.31'
,p_release=>'24.1.0'
,p_default_workspace_id=>4100
,p_default_application_id=>200
,p_default_id_offset=>0
,p_default_owner=>'SALES'
);
end;
/
prompt --application/create_application
begin
wwv_flow_imp.create_flow(
 p_id=>wwv_flow.g_flow_id
,p_owner=>nvl(wwv_flow_application_install.get_schema,'SALES')
,p_name=>nvl(wwv_flow_application_install.get_application_name,'Sales Portal')
,p_alias=>nvl(wwv_flow_application_install.get_application_alias,'SALES')
,p_page_view_logging=>'YES'
,p_page_protection_enabled_y_n=>'Y'
,p_checksum_salt_last_reset=>'20240601000000'
,p_bookmark_checksum_function=>'SH512'
,p_flow_language=>'ar'
,p_flow_language_derived_from=>'FLOW_PRIMARY_LANGUAGE'
,p_authentication_id=>wwv_flow_imp.id(20001)
,p_application_tab_set=>1
,p_public_user=>'APEX_PUBLIC_USER'
,p_proxy_server=>nvl(wwv_flow_application_install.get_proxy,'')
,p_flow_version=>'Release 1.0'
,p_flow_status=>'AVAILABLE_W_DEV_TOOLBAR'
,p_exact_substitutions_only=>'Y'
,p_browser_cache=>'N'
,p_browser_frame=>'D'
,p_rejoin_existing_sessions=>'N'
,p_html_escaping_mode=>'E'
,p_security_scheme=>wwv_flow_imp.id(20002)
,p_file_prefix=>nvl(wwv_flow_application_install.get_static_app_file_prefix,'')
,p_version_scn=>41234567
);
end;
/
prompt --application/shared_components/user_interface/user_interfaces
begin
wwv_flow_imp_shared.create_user_interface(
 p_id=>wwv_flow_imp.id(20003)
,p_theme_id=>42
,p_home_url=>'f?p=&APP_ID.:1:&APP_SESSION.::&DEBUG.:::'
,p_login_url=>'f?p=&APP_ID.:LOGIN:&APP_SESSION.::&DEBUG.:::'
,p_theme_style_by_user_pref=>false
,p_navigation_list_position=>'SIDE'
);
end;
/
prompt --application/shared_components/security/authentications/application_express_accounts
begin
wwv_flow_imp_shared.create_authentication(
 p_id=>wwv_flow_imp.id(20001)
,p_name=>'Oracle APEX Accounts'
,p_scheme_type=>'NATIVE_APEX_ACCOUNTS'
,p_invalid_session_type=>'LOGIN'
,p_use_secure_cookie_yn=>'N'
,p_ras_mode=>0
);
end;
/
prompt --application/shared_components/plugins/region_type/com_acme_chart
begin
wwv_flow_imp_shared.create_plugin(
 p_id=>wwv_flow_imp.id(20101)
,p_plugin_type=>'REGION TYPE'
,p_name=>'COM.ACME.CHART'
,p_display_name=>'Acme Chart'
,p_supported_component_types=>'APEX_APPLICATION_PAGE_REGIONS'
,p_plsql_code=>wwv_flow_string.join(wwv_flow_t_varchar2(
'function render (',
'    p_region              in apex_plugin.t_region,',
'    p_plugin              in apex_plugin.t_plugin,',
'    p_is_printer_friendly in boolean )',
'    return apex_plugin.t_region_render_result',
'is',
'    l_pkg    varchar2(128) := p_region.attribute_01;',
'    l_result apex_plugin.t_region_render_result;',
'begin',
'    if not regexp_like(l_pkg, ''^[A-Za-z][A-Za-z0-9_$#]{0,29}$'') then',
'        raise_application_error(-20001, ''Invalid renderer package'');',
'    end if;',
'    execute immediate ''begin '' || l_pkg || ''.render(p_id => :1, p_filter => :2); end;''',
'      using p_region.static_id, apex_application.g_x01;',
'    return l_result;',
'end render;'))
,p_api_version=>2
,p_render_function=>'render'
,p_standard_attributes=>'SOURCE_LOCATION'
,p_substitute_attributes=>true
,p_subscribe_plugin_settings=>true
,p_version_identifier=>'1.0'
);
wwv_flow_imp_shared.create_plugin_attribute(
 p_id=>wwv_flow_imp.id(20102)
,p_plugin_id=>wwv_flow_imp.id(20101)
,p_attribute_scope=>'COMPONENT'
,p_attribute_sequence=>1
,p_display_sequence=>10
,p_prompt=>'Renderer package'
,p_attribute_type=>'TEXT'
,p_is_required=>true
,p_is_translatable=>false
);
end;
/
prompt --application/shared_components/plugins/region_type/com_acme_legacy_grid
begin
wwv_flow_imp_shared.create_plugin(
 p_id=>wwv_flow_imp.id(20201)
,p_plugin_type=>'REGION TYPE'
,p_name=>'COM.ACME.LEGACY_GRID'
,p_display_name=>'Acme Legacy Grid'
,p_supported_component_types=>'APEX_APPLICATION_PAGE_REGIONS'
,p_plsql_code=>wwv_flow_string.join(wwv_flow_t_varchar2(
'function render (',
'    p_region              in apex_plugin.t_region,',
'    p_plugin              in apex_plugin.t_plugin,',
'    p_is_printer_friendly in boolean )',
'    return apex_plugin.t_region_render_result',
'is',
'    l_result apex_plugin.t_region_render_result;',
'begin',
'    htp.p(''<div class="grid">'' || apex_application.g_x05 || ''</div>'');',
'    return l_result;',
'end render;'))
,p_api_version=>2
,p_render_function=>'render'
,p_substitute_attributes=>true
,p_version_identifier=>'0.9'
);
end;
/
prompt --application/pages/page_00001
begin
wwv_flow_imp_page.create_page(
 p_id=>1
,p_name=>'Home'
,p_alias=>'HOME'
,p_step_title=>'Sales Portal'
,p_autocomplete_on_off=>'OFF'
,p_page_template_options=>'#DEFAULT#'
,p_protection_level=>'C'
,p_page_component_map=>'03'
);
wwv_flow_imp_page.create_page_plug(
 p_id=>wwv_flow_imp.id(30101)
,p_plug_name=>'Sales Chart'
,p_region_template_options=>'#DEFAULT#'
,p_plug_template=>wwv_flow_imp.id(1001)
,p_plug_display_sequence=>10
,p_plug_source_type=>'PLUGIN_COM.ACME.CHART'
,p_attribute_01=>'acme_chart_renderer'
);
end;
/
prompt --application/pages/page_00030
begin
wwv_flow_imp_page.create_page(
 p_id=>30
,p_name=>'Feedback'
,p_alias=>'FEEDBACK'
,p_step_title=>'Feedback'
,p_page_is_public_y_n=>'Y'
,p_protection_level=>'C'
,p_page_component_map=>'16'
);
wwv_flow_imp_page.create_page_process(
 p_id=>wwv_flow_imp.id(30301)
,p_process_sequence=>10
,p_process_point=>'AFTER_SUBMIT'
,p_process_type=>'NATIVE_PLSQL'
,p_process_name=>'Save Feedback'
,p_process_sql_clob=>'insert into feedback (body, created_on) values (:P30_BODY, sysdate);'
,p_process_clob_language=>'PLSQL'
,p_error_display_location=>'INLINE_IN_NOTIFICATION'
);
end;
/
prompt --application/pages/page_09999
begin
wwv_flow_imp_page.create_page(
 p_id=>9999
,p_name=>unistr('\062A\0633\062C\064A\0644 \0627\0644\062F\062E\0648\0644')
,p_alias=>'LOGIN'
,p_step_title=>'Sales Portal - Sign In'
,p_warn_on_unsaved_changes=>'N'
,p_first_item=>'AUTO_FIRST_ITEM'
,p_autocomplete_on_off=>'OFF'
,p_step_template=>wwv_flow_imp.id(1002)
,p_page_template_options=>'#DEFAULT#'
,p_page_is_public_y_n=>'Y'
,p_protection_level=>'U'
,p_page_component_map=>'12'
);
wwv_flow_imp_page.create_page_item(
 p_id=>wwv_flow_imp.id(39991)
,p_name=>'P9999_USERNAME'
,p_item_sequence=>10
,p_prompt=>'Username'
,p_display_as=>'NATIVE_TEXT_FIELD'
,p_cSize=>40
,p_cMaxlength=>100
,p_attribute_01=>'N'
);
wwv_flow_imp_page.create_page_item(
 p_id=>wwv_flow_imp.id(39992)
,p_name=>'P9999_PASSWORD'
,p_item_sequence=>20
,p_prompt=>'Password'
,p_display_as=>'NATIVE_PASSWORD'
,p_cSize=>40
,p_cMaxlength=>100
,p_attribute_01=>'Y'
);
wwv_flow_imp_page.create_page_process(
 p_id=>wwv_flow_imp.id(39993)
,p_process_sequence=>10
,p_process_point=>'AFTER_SUBMIT'
,p_process_type=>'NATIVE_PLSQL'
,p_process_name=>'Set Username Cookie'
,p_process_sql_clob=>wwv_flow_string.join(wwv_flow_t_varchar2(
'apex_authentication.send_login_username_cookie (',
'    p_username => lower(:P9999_USERNAME),',
'    p_consent  => :P9999_REMEMBER = ''Y'' );'))
,p_process_clob_language=>'PLSQL'
);
wwv_flow_imp_page.create_page_process(
 p_id=>wwv_flow_imp.id(39994)
,p_process_sequence=>20
,p_process_point=>'AFTER_SUBMIT'
,p_process_type=>'NATIVE_PLSQL'
,p_process_name=>'Login'
,p_process_sql_clob=>wwv_flow_string.join(wwv_flow_t_varchar2(
'apex_authentication.login(',
'    p_username => :P9999_USERNAME,',
'    p_password => :P9999_PASSWORD );'))
,p_process_clob_language=>'PLSQL'
);
wwv_flow_imp_page.create_page_process(
 p_id=>wwv_flow_imp.id(39995)
,p_process_sequence=>30
,p_process_point=>'AFTER_SUBMIT'
,p_process_type=>'NATIVE_SESSION_STATE'
,p_process_name=>'Clear Page(s) Cache'
,p_attribute_01=>'CLEAR_CACHE_CURRENT_PAGE'
);
wwv_flow_imp_page.create_page_process(
 p_id=>wwv_flow_imp.id(39996)
,p_process_sequence=>10
,p_process_point=>'BEFORE_HEADER'
,p_process_type=>'NATIVE_PLSQL'
,p_process_name=>'Get Username Cookie'
,p_process_sql_clob=>wwv_flow_string.join(wwv_flow_t_varchar2(
':P9999_USERNAME := apex_authentication.get_login_username_cookie;',
':P9999_REMEMBER := case when :P9999_USERNAME is not null then ''Y'' end;'))
,p_process_clob_language=>'PLSQL'
);
end;
/
prompt --application/end_environment
begin
wwv_flow_imp.import_end(p_auto_install_sup_obj => nvl(wwv_flow_application_install.get_auto_install_sup_obj, false));
commit;
end;
/
set verify on feedback on define on
prompt  ...done
