; ========================================================
; GameArt Toolkit - Inno Setup 现代化单文件安装包配置
; ========================================================

#define MyAppName "GameArt Toolkit"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "GameArt Project"
#define MyAppURL "https://github.com/yimoyimoyi/PixivToolkit"
#define MyAppExeName "GameArtToolkit.exe"
#define SourceDir "dist\GameArtToolkit"

[Setup]
; 唯一 GUID (请勿随意变更以确保覆盖升级正常识别)
AppId={{D3F9E123-4A5B-6C7D-8E9F-0A1B2C3D4E5F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; 提升至管理员权限 (用于写入 Program Files 与后续 Hosts/端口接管)
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=dist
OutputBaseFilename=GameArtToolkit_Setup_v{#MyAppVersion}
SetupIconFile=app\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} (卸载)

[Languages]
Name: "chinesesimp"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "quicklaunchicon"; Description: "创建快速启动栏图标"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; 打包便携目录下的所有文件与子目录
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"
Name: "{group}\卸载 {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Run]
; 安装完成后提供勾选立即启动主程序
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
// 辅助函数: 静默终止指定进程
procedure KillProcess(const ExeName: String);
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/F /IM ' + ExeName, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// 1. 安装前初始化: 关闭正在运行的程序和 Nginx 守护进程，防止文件被锁
function InitializeSetup(): Boolean;
begin
  KillProcess('GameArtToolkit.exe');
  KillProcess('PixivToolkit.exe');
  KillProcess('nginx.exe');
  Result := True;
end;

// 2. 卸载前初始化: 关闭进程，并静默执行 Hosts 规则还原
function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
  AppExePath: String;
begin
  // 先终止相关进程
  KillProcess('GameArtToolkit.exe');
  KillProcess('PixivToolkit.exe');
  KillProcess('nginx.exe');
  
  // 静默还原系统 Hosts，杜绝卸载后断网残留
  AppExePath := ExpandConstant('{app}\GameArtToolkit.exe');
  if FileExists(AppExePath) then
  begin
    Exec(AppExePath, '--clean-hosts-silent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  
  Result := True;
end;

// 3. 卸载后置清理: 清理运行时动态产生的临时文件与缓存目录
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DelTree(ExpandConstant('{app}\nginx\cache'), True, True, True);
    DelTree(ExpandConstant('{app}\nginx\logs'), True, True, True);
    DelTree(ExpandConstant('{app}\nginx\temp'), True, True, True);
    DelTree(ExpandConstant('{app}\nginx\ca'), True, True, True);
    DelTree(ExpandConstant('{app}\backups'), True, True, True);
    DelTree(ExpandConstant('{app}'), True, True, True);
  end;
end;
