; Kashif setup wizard for Windows (Inno Setup 6).
;
; Builds kashif-setup.exe: a standard installer that asks where to install, puts kashif.exe there, adds the folder
; to PATH (optional), creates Start-menu / desktop shortcuts for the web interface, and registers an uninstaller.
; The program is bundled inside the setup, so installing needs no network and installs exactly the binary that
; the release's SHA256SUMS.txt lists.
;
; Build (on Windows, from the repository root):
;   iscc /DAppVersion=1.0.0 /DSourceExe=dist\kashif.exe /O. packaging\windows\kashif.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceExe
  #define SourceExe "..\..\dist\kashif.exe"
#endif

[Setup]
AppId={{6F3C9B52-8E1A-4C7D-9B0E-4A2F5D8C1E73}
AppName=Kashif
AppVersion={#AppVersion}
AppVerName=Kashif {#AppVersion}
AppPublisher=Kashif
AppPublisherURL=https://abdulrahmanahmedelabed-prog.github.io/vulnscan/
AppSupportURL=https://github.com/abdulrahmanahmedelabed-prog/vulnscan/issues
AppUpdatesURL=https://github.com/abdulrahmanahmedelabed-prog/vulnscan/releases
; per-user by default (no admin prompt, and the in-app updater can replace the binary);
; the user may switch to "all users" on the first page
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline dialog
DefaultDirName={autopf}\Kashif
DisableDirPage=no
DisableProgramGroupPage=yes
UsePreviousAppDir=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes
OutputBaseFilename=kashif-setup
SetupIconFile=kashif.ico
UninstallDisplayIcon={app}\kashif.exe
UninstallDisplayName=Kashif
LicenseFile=..\..\LICENSE
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
ShowLanguageDialog=auto
VersionInfoVersion={#AppVersion}
VersionInfoProductName=Kashif
VersionInfoDescription=Kashif setup

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
#if FileExists(AddBackslash(CompilerPath) + "Languages\Arabic.isl")
Name: "ar"; MessagesFile: "compiler:Languages\Arabic.isl"
#endif

[CustomMessages]
en.AddToPath=Add Kashif to PATH (use "kashif" from any terminal)
en.DesktopIcon=Create a desktop shortcut
en.OpenUI=Open Kashif now
en.UIShortcut=Kashif
en.UIComment=Open the Kashif web interface
#if FileExists(AddBackslash(CompilerPath) + "Languages\Arabic.isl")
ar.AddToPath=أضف كاشِف إلى PATH (لتشغيل kashif من أي طرفية)
ar.DesktopIcon=أنشئ اختصارًا على سطح المكتب
ar.OpenUI=افتح كاشِف الآن
ar.UIShortcut=كاشِف
ar.UIComment=افتح واجهة كاشِف
#endif

[Tasks]
Name: "addtopath"; Description: "{cm:AddToPath}"
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; Flags: unchecked

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; DestName: "kashif.exe"; Flags: ignoreversion
; compatibility name for scripts written for older versions
Source: "vulnscan.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "kashif.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{cm:UIShortcut}"; Filename: "{app}\kashif.exe"; Parameters: "ui"; IconFilename: "{app}\kashif.ico"; Comment: "{cm:UIComment}"
Name: "{autodesktop}\{cm:UIShortcut}"; Filename: "{app}\kashif.exe"; Parameters: "ui"; IconFilename: "{app}\kashif.ico"; Comment: "{cm:UIComment}"; Tasks: desktopicon

[Run]
Filename: "{app}\kashif.exe"; Parameters: "ui"; Description: "{cm:OpenUI}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; files the in-app updater may leave next to the binary: the backup of the previous version, and the temporary
; download of an update that was interrupted (tempfile.mkstemp(prefix=".vulnscan-update-", suffix=".exe") in
; vulnscan/updater.py; .kashif-update-* is listed too so a later rename of that prefix is still cleaned up)
Type: files; Name: "{app}\kashif.exe.old"
Type: files; Name: "{app}\kashif.exe.new"
Type: files; Name: "{app}\.vulnscan-update-*"
Type: files; Name: "{app}\.kashif-update-*"

[Code]
function EnvKey: string;
begin
  if IsAdminInstallMode then
    Result := 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  else
    Result := 'Environment';
end;

function EnvRoot: Integer;
begin
  if IsAdminInstallMode then Result := HKEY_LOCAL_MACHINE else Result := HKEY_CURRENT_USER;
end;

function PathHas(const Paths, Dir: string): Boolean;
begin
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') > 0;
end;

procedure AddToPath(const Dir: string);
var Paths: string;
begin
  if not RegQueryStringValue(EnvRoot, EnvKey, 'Path', Paths) then Paths := '';
  if PathHas(Paths, Dir) then exit;
  if (Paths <> '') and (Copy(Paths, Length(Paths), 1) <> ';') then Paths := Paths + ';';
  RegWriteExpandStringValue(EnvRoot, EnvKey, 'Path', Paths + Dir);
end;

procedure RemoveFromPath(const Dir: string);
var Paths: string; P: Integer;
begin
  if not RegQueryStringValue(EnvRoot, EnvKey, 'Path', Paths) then exit;
  Paths := ';' + Paths + ';';
  P := Pos(';' + Uppercase(Dir) + ';', Uppercase(Paths));
  if P = 0 then exit;
  Delete(Paths, P, Length(Dir) + 1);
  Paths := Copy(Paths, 2, Length(Paths) - 2);
  RegWriteExpandStringValue(EnvRoot, EnvKey, 'Path', Paths);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then
    AddToPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
