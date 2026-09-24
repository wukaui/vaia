/*
  教学演示用 YARA 规则。
  比赛时可把公开规则库精选后放到本目录，支持多个 .yar/.yara 文件。
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test marker"
        author = "ai-av-cli"
        severity = "high"
    strings:
        $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii wide nocase
    condition:
        $e
}

rule Suspicious_PowerShell_Download
{
    meta:
        description = "PowerShell 下载/执行特征，要求同时出现 2 个以上，避免单字面量误报"
        author = "ai-av-cli"
        severity = "medium"
        tuning = "2026-09-19：any of them -> 2 of them。实测 any of them 会在微软签名系统 DLL、Qt WebEngine、CMake 等合法二进制上命中（只因含 DownloadFile 字样），3367 个良性文件里产生 6 个误报"
    strings:
        $a = "DownloadString" nocase
        $b = "DownloadFile" nocase
        $c = "Invoke-Expression" nocase
        $d = "FromBase64String" nocase
        $e = "-EncodedCommand" nocase
    condition:
        2 of them
}

rule Suspicious_Office_AutoOpen
{
    meta:
        description = "Office 文档（OLE/OOXML 容器）中的宏自动执行入口"
        author = "ai-av-cli"
        severity = "medium"
        tuning = "2026-09-19：要求文件是 OLE 复合文档或 ZIP/OOXML 容器。原规则不区分文件类型，PyMuPDF 原生扩展 _mupdf.pyd 因含 document_open 字面量被误报"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $zip = { 50 4B 03 04 }
        $a = "AutoOpen" nocase
        $b = "Document_Open" nocase
        $c = "Workbook_Open" nocase
    condition:
        ($ole at 0 or $zip at 0) and any of ($a, $b, $c)
}

rule Suspicious_Process_Injection_APIs
{
    meta:
        description = "Common process injection APIs"
        severity = "medium"
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
        $d = "NtCreateThreadEx" ascii
    condition:
        2 of them
}

rule Suspicious_LNK_Execution
{
    meta:
        description = "LNK 指向 LOLBin 或远程载荷，并带隐藏窗口/编码命令参数"
        author = "ai-av-cli"
        severity = "high"
    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $ps = "powershell" wide ascii nocase
        $mshta = "mshta" wide ascii nocase
        $rundll = "rundll32" wide ascii nocase
        $regsvr = "regsvr32" wide ascii nocase
        $certutil = "certutil" wide ascii nocase
        $bits = "bitsadmin" wide ascii nocase
        $wmic = "wmic" wide ascii nocase
        $enc = "-enc" wide ascii nocase
        $hidden = "hidden" wide ascii nocase
        $http = "http://" wide ascii nocase
        $https = "https://" wide ascii nocase
    condition:
        $lnk at 0 and
        (1 of ($ps, $mshta, $rundll, $regsvr, $certutil, $bits, $wmic))
        and (1 of ($enc, $hidden, $http, $https))
}

rule Suspicious_RTF_Remote_Object
{
    meta:
        description = "RTF 内嵌/链接远程对象（钓鱼投递与漏洞利用常见手法）"
        author = "ai-av-cli"
        severity = "high"
    strings:
        $rtf = "{\\rtf" ascii
        $objlink = "\\objlink" ascii nocase
        $objupdate = "\\objupdate" ascii nocase
        $objdata = "\\objdata" ascii nocase
        $eqn = "equation.3" ascii nocase
        $http = "http://" ascii nocase
        $https = "https://" ascii nocase
    condition:
        $rtf at 0 and
        (
            (($objlink or $objupdate) and ($http or $https))
            or ($objdata and $eqn)
        )
}

/*
  2026-09-19 补强：确定性规则 5 条（每条都在 meta.benign_expectation 里写清"良性不该命中"的反向断言）
  原则：只写"结构上可判定"的组合条件，且要求多个特征同时成立 ——
  单字面量规则正是 2026-09-19 那批误报的根源（见 docs/FP_ROOT_CAUSE_FIXES.md）。
*/

rule Suspicious_PowerShell_Download_Exec
{
    meta:
        description = "PowerShell 下载并执行：下载原语 + 执行原语同时出现（缺一不判）"
        author = "ai-av-cli"
        severity = "high"
        benign_expectation = "良性不该命中：只下载不执行（发布脚本、健康检查、补丁脚本）；用 Start-Process 起本地程序也不算；文件不能是 PE/DLL（避免合法二进制里含这些字面量）"
    strings:
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "Invoke-WebRequest" nocase
        $dl4 = "Net.WebClient" nocase
        $ex1 = "Invoke-Expression" nocase
        $ex2 = "IEX " nocase
        $ex3 = "-EncodedCommand" nocase
        $mz = { 4D 5A }
    condition:
        // 只认"下载 + 执行下载物"的组合（IEX / Invoke-Expression / -EncodedCommand）：
        // Start-Process 这类正常运维也会用的原语不算；PE 一律不看（合法二进制里全是这些字面量）
        not $mz at 0 and
        (1 of ($dl1, $dl2, $dl3, $dl4)) and
        (1 of ($ex1, $ex2, $ex3))
}

rule Suspicious_LNK_Double_Extension
{
    meta:
        description = "LNK 双扩展名**可执行体**：文件名/目标把文档扩展名藏在可执行扩展名前面（invoice.pdf.exe）"
        author = "ai-av-cli"
        severity = "high"
        benign_expectation = "良性不该命中：正常快捷方式（notepad.exe + notes.txt、WINWORD.EXE + report.docx）里文档扩展名与 .exe 是**分开的两段**，只有相邻式双扩展名才算证据"
        tuning = "2026-09-19 收窄：旧写法只要『出现文档扩展名』且『出现 .exe』就命中，于是把『用 Word 打开 report.docx』这类良性快捷方式全打成可疑（合成矩阵 100 个良性 LNK 里 30 个中招）。改为相邻式正则，且不再单独索要 $exe。"
    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $de = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|zip)\.(exe|scr|bat|cmd|com|pif|ps1|vbs|js|hta)/ wide ascii nocase
    condition:
        $lnk at 0 and $de
}

rule Suspicious_Office_Macro_NonAutoOpen_Entry
{
    meta:
        description = "Office 宏的非 AutoOpen 入口（Auto_Close / Document_BeforeClose / Workbook_BeforeSave / AutoNew）+ 命令执行或下载 API"
        author = "ai-av-cli"
        severity = "medium"
        benign_expectation = "良性不该命中：只有 AutoOpen/Document_Open 这类正常入口、或没有下载/执行 API 的宏文档不得命中（正常宏文档太多，单入口名不构成证据）"
        tuning = "2026-09-19：入口名必须与下载/执行 API 同现，避免把所有带宏的文档拉进可疑"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $zip = { 50 4B 03 04 }
        $e1 = "Document_BeforeClose" nocase
        $e2 = "Workbook_BeforeSave" nocase
        $e3 = "Auto_Close" nocase
        $e4 = "AutoNew" nocase
        $e5 = "DocumentBeforeClose" nocase
        $api1 = "URLDownloadToFile" nocase
        $api2 = "WScript.Shell" nocase
        $api3 = "Shell.Application" nocase
        $api4 = "WinHttp" nocase
        $api5 = "CreateObject" nocase
    condition:
        ($ole at 0 or $zip at 0) and (1 of ($e1, $e2, $e3, $e4, $e5)) and (1 of ($api1, $api2, $api3, $api4, $api5))
}

rule Suspicious_RTF_Object_Injection
{
    meta:
        description = "RTF 对象注入：\\objdata 内嵌对象 + 可执行/脚本载荷（equation 漏洞链常用 combo）"
        author = "ai-av-cli"
        severity = "high"
        benign_expectation = "良性不该命中：正常 RTF（会议纪要这类纯文本排版）没有 \\objdata，也不含 exe/dll/hta/script 载荷名；单独的公式对象不算"
    strings:
        $rtf = "{\\rtf" ascii
        $objdata = "\\objdata" ascii nocase
        $p1 = ".exe" ascii nocase wide
        $p2 = ".dll" ascii nocase wide
        $p3 = ".hta" ascii nocase wide
        $p4 = "mshta" ascii nocase wide
        $p5 = "scrobj" ascii nocase wide
        $p6 = "wscript" ascii nocase wide
    condition:
        $rtf at 0 and $objdata and (1 of ($p1, $p2, $p3, $p4, $p5, $p6))
}

rule Suspicious_Script_EncodedCommand_Chain
{
    meta:
        description = "脚本编码命令链：-enc/-EncodedCommand + 长 base64 + 解码或执行原语"
        author = "ai-av-cli"
        severity = "high"
        benign_expectation = "良性不该命中：① 合法模块（如 Windows 自带的 PSDesiredStateConfiguration.psm1）也会用 -EncodedCommand 与 base64，只要没有解码/执行原语或隐藏窗口就不算；② PE/DLL 一律不看（CMake/Qt/mspdf/驱动等合法二进制里就嵌着这类命令文本）；③ 含长 base64 常量但没有解码/执行原语的数据脚本不得命中；④ 散文类文本（本地化 .pak 里出现「-e 」后接单词）不得命中 —— 参数与载荷必须相邻"
    strings:
        // 参数与载荷必须**相邻**：写成两条正则，避免"散文里恰好出现 -e 和一段长串"这种巧合
        $enc1 = /-EncodedCommand\s+["']?[A-Za-z0-9+\/]{60,}={0,2}/ nocase ascii
        $enc2 = /-e\s+["']?[A-Za-z0-9+\/]{60,}={0,2}/ nocase ascii
        $encw1 = /-EncodedCommand/ nocase wide
        $encw2 = /-e\s/ nocase wide
        $d1 = "FromBase64String" nocase
        $d2 = "[char]" nocase
        $d3 = "Invoke-Expression" nocase
        $d4 = "IEX" nocase
        $hidden = "-w hidden" nocase
        $hidden2 = "-windowstyle hidden" nocase
        $mz = { 4D 5A }
    condition:
        // 编码命令 + 长 base64 + （解码/执行原语 或 隐藏窗口）——
        // 单靠"-e <base64>"不判（合法模块也会用编码命令），必须与"要藏起来"的意图同现。
        // PE 一律不看：实测 CMake / Qt / mspdf / 驱动等合法二进制里就嵌着 PowerShell 命令文本，
        // 只看文本会把它们全打成"脚本编码命令链"（2026-09-19 全量良性回归抓到 16 个这样的误报）。
        not $mz at 0 and
        (1 of ($enc1, $enc2, $encw1, $encw2))
        and (1 of ($d1, $d2, $d3, $d4, $hidden, $hidden2))
}
