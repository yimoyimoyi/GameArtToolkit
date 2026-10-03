; ========================================================
; GameArt Toolkit - Inno Setup 现代化单文件安装包配置
; ========================================================

#define MyAppName "GameArt Toolkit"
#define MyAppVersion "1.1.0"
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
; 强制提升至管理员权限 (启动安装包时即弹出 UAC 提权)
PrivilegesRequired=admin
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

// 2. 卸载前初始化: 关闭进程，并静默执行**完整**还原
function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
  AppExePath: String;
begin
  // 先终止相关进程
  KillProcess('GameArtToolkit.exe');
  KillProcess('PixivToolkit.exe');
  KillProcess('nginx.exe');

  // ★ 卸载必须还原**全部六处**系统级改动, 而且必须在下面的 [UninstallDelete]/
  //   CurUninstallStepChanged 删掉 {app} 之前执行 (缺陷 W7, 2026-10-04)。
  //
  //   原先这里只调用 `--clean-hosts-silent`, 于是卸载会留下:
  //     · 系统代理 AutoConfigURL 仍指着 http://127.0.0.1:44501/proxy.pac, 而该端口
  //       随程序一起消失 ⇒ **所有 WinINET 应用**(不只浏览器)每次取自动配置都对着
  //       死端口等到超时, 用户感知为"卸载之后上网变卡/时好时坏";
  //     · NRPT 规则 (用过该模式的话) —— 残留会把整机解析指向已停止的本地解析器;
  //     · 已装进信任库的自签根 —— 文件被删而根还在, 留下一个"私钥已丢失的受信任
  //       签发者", 这是用户最难自查的一类残留;
  //     · 自启计划任务与启动文件夹快捷方式 —— 登录时静默启动一个已不存在的 exe;
  //     · git 全局配置的改写。
  //   一次性调用 `--clean-all-silent` 覆盖以上全部; 该 CLI 分支复用已测试的清理路径,
  //   且每步独立、逐条打印, 一条失败不影响其余。
  AppExePath := ExpandConstant('{app}\GameArtToolkit.exe');
  if FileExists(AppExePath) then
  begin
    Exec(AppExePath, '--clean-all-silent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end
  else
  begin
    // exe 已不在 (例如上一次卸载中断): 尽力清掉系统代理残留, 它是唯一会让用户
    // "卸载后上不了网"的一项。用 reg 直接删, 不依赖 {app} 下任何文件。
    Exec('reg.exe',
         'delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL /f',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
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
