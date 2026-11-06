prompt --application/pages/page_00030
begin
wwv_flow_imp_page.create_page(
 p_id=>30
,p_name=>'Edit Note'
);
wwv_flow_imp_page.create_page_plug(
 p_id=>wwv_flow_imp.id(3001)
,p_plug_name=>'Note'
,p_query_type=>'TABLE'
,p_query_table=>'NOTES'
,p_plug_source_type=>'NATIVE_FORM'
);
wwv_flow_imp_page.create_page_item(
 p_id=>wwv_flow_imp.id(3002)
,p_name=>'P30_BODY'
,p_source_plug_id=>wwv_flow_imp.id(3001)
,p_item_source_plug_id=>wwv_flow_imp.id(3001)
,p_source=>'BODY'
,p_source_type=>'REGION_SOURCE_COLUMN'
,p_display_as=>'NATIVE_TEXTAREA'
);
wwv_flow_imp_page.create_page_item(
 p_id=>wwv_flow_imp.id(3003)
,p_name=>'P30_STATUS'
,p_item_source_plug_id=>wwv_flow_imp.id(3001)
,p_source=>'STATUS'
,p_source_type=>'REGION_SOURCE_COLUMN'
);
end;
/
prompt --application/pages/page_00031
begin
wwv_flow_imp_page.create_page(
 p_id=>31
,p_name=>'Notes Board'
);
wwv_flow_imp_page.create_page_plug(
 p_id=>wwv_flow_imp.id(3101)
,p_plug_name=>'Board'
,p_plug_source=>wwv_flow_string.join(wwv_flow_t_varchar2(
'begin',
'  for r in (select body, status from notes order by id desc) loop',
'    htp.p(''<div class="note">'' || r.body || ''</div>'');',
'    htp.p(''<span>'' || r.status || ''</span>'');',
'    htp.p(''<div>'' || apex_escape.html(r.body) || ''</div>'');',
'  end loop;',
'end;'))
,p_plug_source_type=>'NATIVE_PLSQL'
);
end;
/
