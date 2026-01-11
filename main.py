# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Project Name: Kali Nmap MCP
Author: LyShark
Email: admin@lyshark.com
Creation date: January 11, 2026
Function description: Remote execution of Nmap scan through SSH persistent connection, returning XML format results
License: MIT
Version: v1.0
"""
import paramiko
import os
from typing import Optional, Dict, Any
from contextlib import contextmanager
from fastmcp import FastMCP
from datetime import datetime

terminal_manager: Optional["RemoteSSHSyncPersistentExecutor"] = None
mcp = FastMCP("Kali Nmap MCP")

SSH_CONFIG = {
    "hostname": "127.0.0.1",
    "username": "lyshark",
    "password": "lyshark",
    "port": 22,
    "command_timeout": 600,
    "sftp_timeout": 120
}

class RemoteSSHSyncPersistentExecutor:
    """
    SSH持久连接执行器（同步版）
    特性：自动维护SSH长连接，连接失效时自动重建，支持命令超时控制，完善的错误处理
    新增功能：文件上传、文件下载、读取远程文本文件内容
    """

    def __init__(
            self,
            hostname: str,
            username: str,
            password: str,
            port: int = 22,
            ssh_timeout: int = 15,
            command_timeout: int = 600,
            sftp_timeout: int = 60
    ):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.ssh_timeout = ssh_timeout
        self.command_timeout = command_timeout
        self.sftp_timeout = sftp_timeout
        self._ssh_client: Optional[paramiko.SSHClient] = None
        self._sftp_client: Optional[paramiko.SFTPClient] = None
        self._connect_time: Optional[datetime] = None

    def _is_ssh_active(self) -> bool:
        """私有方法：校验当前SSH持久连接是否处于活跃状态"""
        if not self._ssh_client:
            return False
        try:
            transport = self._ssh_client.get_transport()
            if transport and transport.is_active():
                transport.send_ignore()
                return True
            return False
        except Exception as e:
            return False

    def _create_ssh_client(self) -> paramiko.SSHClient:
        """私有方法：创建并返回有效SSH客户端连接"""
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                hostname=self.hostname,
                username=self.username,
                password=self.password,
                port=self.port,
                timeout=self.ssh_timeout,
                allow_agent=False,
                look_for_keys=False
            )
            self._connect_time = datetime.now()

            return ssh_client
        except paramiko.AuthenticationException:
            raise Exception(f"SSH认证失败：用户名/密码错误（主机: {self.hostname}）")
        except paramiko.NoValidConnectionsError:
            raise Exception(f"SSH连接失败：无法连接到 {self.hostname}:{self.port}（端口/网络问题）")
        except Exception as e:
            raise Exception(f"SSH连接创建失败（主机: {self.hostname}）：{str(e)}")

    def _create_sftp_client(self) -> paramiko.SFTPClient:
        """私有方法：创建并返回有效SFTP客户端"""
        if not self._ssh_client or not self._is_ssh_active():
            raise Exception("无法创建SFTP客户端：SSH连接未建立或已失效")

        try:
            sftp_client = self._ssh_client.open_sftp()
            sftp_client.get_channel().settimeout(self.sftp_timeout)
            return sftp_client
        except Exception as e:
            raise Exception(f"SFTP客户端创建失败（主机: {self.hostname}）：{str(e)}")

    def _ensure_ssh_connection(self) -> None:
        """私有方法：确保持久连接可用（未创建/已失效则自动重建）"""
        if not self._is_ssh_active():
            if self._ssh_client:
                self.close_ssh_connection()
            self._ssh_client = self._create_ssh_client()
            self._sftp_client = None

    def _ensure_sftp_connection(self) -> None:
        """私有方法：确保SFTP客户端可用"""
        self._ensure_ssh_connection()
        if not self._sftp_client or (self._sftp_client.get_channel() is None) or not self._sftp_client.get_channel().active:
            self._sftp_client = self._create_sftp_client()

    @staticmethod
    def _clean_bad_bytes(input_str: Any) -> str:
        """静态方法：清洗字符串中的坏字节，增强鲁棒性"""
        if not isinstance(input_str, str):
            input_str = str(input_str) if input_str is not None else ""
        cleaned_str = "".join(
            c for c in input_str if c.isprintable() or c in ("\n", "\r", "\t")
        ).strip()
        return cleaned_str

    def execute_command_sync(
            self,
            command: str,
            encoding: str = "utf-8"
    ) -> str:
        """
        核心公有方法：复用持久SSH连接，同步执行命令

        Args:
            command: 要执行的Shell命令
            encoding: 输出解码编码（默认utf-8）

        Returns:
            清洗后的命令输出字符串

        Raises:
            ValueError: 命令为空或非字符串
            Exception: 连接/命令执行失败
        """

        if not isinstance(command, str) or not command.strip():
            raise ValueError("执行命令不能为空，且必须为非空字符串类型")
        command = command.strip()

        self._ensure_ssh_connection()

        try:
            stdin, stdout, stderr = self._ssh_client.exec_command(
                command,
                timeout=self.command_timeout
            )

            stdout.channel.settimeout(self.command_timeout)
            stderr.channel.settimeout(self.command_timeout)
            stdout_output = stdout.read().decode(encoding, errors="replace")
            stderr_output = stderr.read().decode(encoding, errors="replace")
            full_output = stdout_output
            if stderr_output:
                full_output += f"\n[STDERR]: {stderr_output}"
            cleaned_output = self._clean_bad_bytes(full_output)

            return cleaned_output

        except TimeoutError:
            self.close_ssh_connection()
            raise Exception(f"命令执行超时（超时时间: {self.command_timeout}秒）：{command}")
        except Exception as e:
            self.close_ssh_connection()
            raise Exception(f"命令执行失败（连接已重置）：{str(e)} | 命令: {command}")

    def upload_file(
            self,
            local_file_path: str,
            remote_file_path: str,
            overwrite: bool = False
    ) -> Dict[str, Any]:
        """
        上传本地文件到远程服务器

        Args:
            local_file_path: 本地文件绝对/相对路径
            remote_file_path: 远程服务器文件路径
            overwrite: 是否覆盖远程已存在的文件（默认False）

        Returns:
            包含上传结果的字典

        Raises:
            FileNotFoundError: 本地文件不存在
            PermissionError: 无权限上传文件
            Exception: SFTP操作失败
        """
        if not os.path.exists(local_file_path):
            raise FileNotFoundError(f"本地文件不存在：{local_file_path}")
        if not os.path.isfile(local_file_path):
            raise ValueError(f"指定路径不是文件：{local_file_path}")

        self._ensure_sftp_connection()

        try:
            remote_file_exists = False
            try:
                self._sftp_client.stat(remote_file_path)
                remote_file_exists = True
            except FileNotFoundError:
                remote_file_exists = False

            if remote_file_exists and not overwrite:
                raise Exception(f"远程文件已存在，且未开启覆盖模式：{remote_file_path}")

            self._sftp_client.put(local_file_path, remote_file_path, confirm=True)

            remote_file_stat = self._sftp_client.stat(remote_file_path)
            local_file_size = os.path.getsize(local_file_path)
            remote_file_size = remote_file_stat.st_size

            if local_file_size != remote_file_size:
                raise Exception(f"文件上传不完整：本地大小{local_file_size}字节，远程大小{remote_file_size}字节")

            result = {
                "status": "success",
                "message": f"文件上传成功",
                "data": {
                    "local_file": local_file_path,
                    "remote_file": remote_file_path,
                    "file_size": local_file_size,
                    "hostname": self.hostname
                }
            }

            return result

        except PermissionError:
            raise Exception(f"无权限上传文件到远程路径：{remote_file_path}（权限被拒绝）")
        except Exception as e:
            self.close_ssh_connection()
            raise Exception(f"文件上传失败：{str(e)}")

    def download_file(
            self,
            remote_file_path: str,
            local_file_path: str,
            overwrite: bool = False
    ) -> Dict[str, Any]:
        """
        从远程服务器下载文件到本地

        Args:
            remote_file_path: 远程服务器文件路径
            local_file_path: 本地保存文件路径
            overwrite: 是否覆盖本地已存在的文件（默认False）

        Returns:
            包含下载结果的字典

        Raises:
            FileNotFoundError: 远程文件不存在
            PermissionError: 无权限读取/写入文件
            Exception: SFTP操作失败
        """

        if os.path.exists(local_file_path) and not overwrite:
            raise Exception(f"本地文件已存在，且未开启覆盖模式：{local_file_path}")

        self._ensure_sftp_connection()

        try:
            try:
                remote_file_stat = self._sftp_client.stat(remote_file_path)
            except FileNotFoundError:
                raise FileNotFoundError(f"远程文件不存在：{remote_file_path}")

            self._sftp_client.get(remote_file_path, local_file_path)

            local_file_size = os.path.getsize(local_file_path)
            remote_file_size = remote_file_stat.st_size

            if local_file_size != remote_file_size:
                os.remove(local_file_path)
                raise Exception(f"文件下载不完整：远程大小{remote_file_size}字节，本地大小{local_file_size}字节")

            result = {
                "status": "success",
                "message": f"文件下载成功",
                "data": {
                    "remote_file": remote_file_path,
                    "local_file": local_file_path,
                    "file_size": remote_file_size,
                    "hostname": self.hostname
                }
            }
            return result

        except PermissionError:
            self.close_ssh_connection()
        except Exception as e:
            self.close_ssh_connection()

    def read_remote_text_file(
            self,
            remote_file_path: str,
            encoding: str = "utf-8",
            start_line: Optional[int] = None,
            end_line: Optional[int] = None,
            clean_bytes: bool = True
    ) -> str:
        """
        读取远程文本文件的内容（支持指定行数范围）

        Args:
            remote_file_path: 远程文本文件路径
            encoding: 文件编码（默认utf-8）
            start_line: 起始行号（从1开始，None表示从第一行开始）
            end_line: 结束行号（None表示到最后一行）
            clean_bytes: 是否清洗坏字节（默认True）

        Returns:
            读取的文本内容字符串

        Raises:
            FileNotFoundError: 远程文件不存在
            ValueError: 行号参数不合法
            Exception: 文件读取失败
        """

        if start_line is not None and start_line < 1:
            raise ValueError(f"起始行号必须大于等于1：{start_line}")
        if end_line is not None and end_line < 1:
            raise ValueError(f"结束行号必须大于等于1：{end_line}")
        if start_line is not None and end_line is not None and start_line > end_line:
            raise ValueError(f"起始行号不能大于结束行号：start={start_line}, end={end_line}")

        self._ensure_sftp_connection()

        try:
            try:
                self._sftp_client.stat(remote_file_path)
            except FileNotFoundError:
                raise FileNotFoundError(f"远程文件不存在：{remote_file_path}")

            with self._sftp_client.open(remote_file_path, "rb") as f:
                binary_content = f.read()
                text_content = binary_content.decode(encoding, errors="replace")
                lines = text_content.splitlines(keepends=True)

            if start_line is not None or end_line is not None:
                start_idx = start_line - 1 if start_line else 0
                end_idx = end_line if end_line else len(lines)
                lines = lines[start_idx:end_idx]

            content = "".join(lines)
            if clean_bytes:
                content = self._clean_bad_bytes(content)
            return content

        except UnicodeDecodeError:
            raise Exception(f"文件编码解析失败：{remote_file_path}（请指定正确的encoding参数，当前：{encoding}）")
        except Exception as e:
            self.close_ssh_connection()
            raise Exception(f"读取远程文件失败：{str(e)}")

    def close_ssh_connection(self) -> Dict[str, Any]:
        """
        公有方法：手动关闭SSH持久连接（包含SFTP客户端）

        Returns:
            包含关闭状态的字典
        """

        if self._sftp_client:
            try:
                self._sftp_client.close()
            except Exception as e:
                self._sftp_client.close()
            finally:
                self._sftp_client = None

        if not self._ssh_client:
            return {
                "status": "success",
                "message": "SSH持久连接未初始化或已关闭",
                "data": None
            }

        try:
            if self._is_ssh_active():
                self._ssh_client.close()
            self._ssh_client = None
            self._connect_time = None
            result = {
                "status": "success",
                "message": f"与 {self.hostname}:{self.port} 的SSH持久连接已成功关闭",
                "data": {"hostname": self.hostname, "port": self.port}
            }
            return result
        except Exception as e:
            self._ssh_client = None
            self._connect_time = None
            result = {
                "status": "warn",
                "message": f"SSH连接关闭异常，已强制置空：{str(e)}",
                "data": None
            }
            return result

    @contextmanager
    def auto_close(self):
        """上下文管理器：自动管理连接（推荐使用）"""
        try:
            yield self
        finally:
            self.close_ssh_connection()

    def __enter__(self):
        """支持with语句"""
        self._ensure_ssh_connection()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """with语句结束时自动关闭连接"""
        self.close_ssh_connection()

    def __del__(self):
        """析构函数：确保连接最终被关闭"""
        self.close_ssh_connection()

    def get_connection_info(self) -> Dict[str, Any]:
        """获取当前连接信息（便于监控）"""
        sftp_active = False
        if self._sftp_client:
            try:
                channel = self._sftp_client.get_channel()
                sftp_active = channel is not None and channel.active
            except:
                sftp_active = False

        return {
            "hostname": self.hostname,
            "port": self.port,
            "username": self.username,
            "is_ssh_active": self._is_ssh_active(),
            "is_sftp_active": sftp_active,
            "connect_time": self._connect_time.strftime("%Y-%m-%d %H:%M:%S") if self._connect_time else None,
            "ssh_timeout": self.ssh_timeout,
            "command_timeout": self.command_timeout,
            "sftp_timeout": self.sftp_timeout
        }

# 扫描执行器
class NmapSSHScanExecutor(RemoteSSHSyncPersistentExecutor):
    def __init__(
            self,
            hostname: str,
            username: str,
            password: str,
            port: int = 22,
            ssh_timeout: int = 15,
            command_timeout: int = 1200,
            sftp_timeout: int = 60,
            default_nmap_args: str = "-sV -Pn -T4 -oX -",
    ):
        super().__init__(
            hostname=hostname,
            username=username,
            password=password,
            port=port,
            ssh_timeout=ssh_timeout,
            command_timeout=command_timeout,
            sftp_timeout=sftp_timeout
        )
        self.default_nmap_args = default_nmap_args

    def run_nmap_scan(
            self,
            target: str,
            nmap_args: Optional[str] = None,
            encoding: str = "utf-8"
    ) -> str:
        """
        执行Nmap扫描

        Args:
            target: 扫描目标（IP/域名/IP段）
            nmap_args: 自定义nmap参数（None则使用默认参数）
            encoding: 输出解码编码（默认utf-8）

        Returns:
            清洗后的扫描结果字符串
        """

        if not target.strip():
            raise ValueError("扫描目标不能为空")

        final_nmap_args = nmap_args if nmap_args is not None else self.default_nmap_args
        nmap_command = f"nmap {final_nmap_args} -oX - {target}"

        stdout = super().execute_command_sync(nmap_command, encoding=encoding)
        return stdout

@mcp.tool()
def nmap_scan(target: str, nmap_args: Optional[str] = None, encoding: str = "utf-8") -> str:
    """
    执行Nmap扫描命令，返回XML格式扫描结果。
    Args:
        target: 扫描目标（IP/域名/IP段，如 192.168.1.0/24、www.lyshark.com）
        nmap_args: 自定义Nmap参数，具体可参考Help部分说明，可组合使用（默认参数：-sV -Pn -T4）
        encoding: 结果解码编码（默认utf-8）
    Returns:
        输出XML格式扫描结果字符串，若执行失败返回错误信息。
    Help:
        Usage: nmap [Scan Type(s)] [Options] {target specification}
        TARGET SPECIFICATION:
          Can pass hostnames, IP addresses, networks, etc.
          Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
          -iL <inputfilename>: Input from list of hosts/networks
          -iR <num hosts>: Choose random targets
          --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
          --excludefile <exclude_file>: Exclude list from file
        HOST DISCOVERY:
          -sL: List Scan - simply list targets to scan
          -sn: Ping Scan - disable port scan
          -Pn: Treat all hosts as online -- skip host discovery
          -PS/PA/PU/PY[portlist]: TCP SYN, TCP ACK, UDP or SCTP discovery to given ports
          -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
          -PO[protocol list]: IP Protocol Ping
          -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
          --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
          --system-dns: Use OS's DNS resolver
          --traceroute: Trace hop path to each host
        SCAN TECHNIQUES:
          -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
          -sU: UDP Scan
          -sN/sF/sX: TCP Null, FIN, and Xmas scans
          --scanflags <flags>: Customize TCP scan flags
          -sI <zombie host[:probeport]>: Idle scan
          -sY/sZ: SCTP INIT/COOKIE-ECHO scans
          -sO: IP protocol scan
          -b <FTP relay host>: FTP bounce scan
        PORT SPECIFICATION AND SCAN ORDER:
          -p <port ranges>: Only scan specified ports
            Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
          --exclude-ports <port ranges>: Exclude the specified ports from scanning
          -F: Fast mode - Scan fewer ports than the default scan
          -r: Scan ports sequentially - don't randomize
          --top-ports <number>: Scan <number> most common ports
          --port-ratio <ratio>: Scan ports more common than <ratio>
        SERVICE/VERSION DETECTION:
          -sV: Probe open ports to determine service/version info
          --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
          --version-light: Limit to most likely probes (intensity 2)
          --version-all: Try every single probe (intensity 9)
          --version-trace: Show detailed version scan activity (for debugging)
        SCRIPT SCAN:
          -sC: equivalent to --script=default
          --script=<Lua scripts>: <Lua scripts> is a comma separated list of
                   directories, script-files or script-categories
          --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
          --script-args-file=filename: provide NSE script args in a file
          --script-trace: Show all data sent and received
          --script-updatedb: Update the script database.
          --script-help=<Lua scripts>: Show help about scripts.
                   <Lua scripts> is a comma-separated list of script-files or
                   script-categories.
        OS DETECTION:
          -O: Enable OS detection
          --osscan-limit: Limit OS detection to promising targets
          --osscan-guess: Guess OS more aggressively
        TIMING AND PERFORMANCE:
          Options which take <time> are in seconds, or append 'ms' (milliseconds),
          's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
          -T<0-5>: Set timing template (higher is faster)
          --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
          --min-parallelism/max-parallelism <numprobes>: Probe parallelization
          --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies
              probe round trip time.
          --max-retries <tries>: Caps number of port scan probe retransmissions.
          --host-timeout <time>: Give up on target after this long
          --scan-delay/--max-scan-delay <time>: Adjust delay between probes
          --min-rate <number>: Send packets no slower than <number> per second
          --max-rate <number>: Send packets no faster than <number> per second
        FIREWALL/IDS EVASION AND SPOOFING:
          -f; --mtu <val>: fragment packets (optionally w/given MTU)
          -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
          -S <IP_Address>: Spoof source address
          -e <iface>: Use specified interface
          -g/--source-port <portnum>: Use given port number
          --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
          --data <hex string>: Append a custom payload to sent packets
          --data-string <string>: Append a custom ASCII string to sent packets
          --data-length <num>: Append random data to sent packets
          --ip-options <options>: Send packets with specified ip options
          --ttl <val>: Set IP time-to-live field
          --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
          --badsum: Send packets with a bogus TCP/UDP/SCTP checksum
        OUTPUT:
          -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,
             and Grepable format, respectively, to the given filename.
          -oA <basename>: Output in the three major formats at once
          -v: Increase verbosity level (use -vv or more for greater effect)
          -d: Increase debugging level (use -dd or more for greater effect)
          --reason: Display the reason a port is in a particular state
          --open: Only show open (or possibly open) ports
          --packet-trace: Show all packets sent and received
          --iflist: Print host interfaces and routes (for debugging)
          --append-output: Append to rather than clobber specified output files
          --resume <filename>: Resume an aborted scan
          --noninteractive: Disable runtime interactions via keyboard
          --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
          --webxml: Reference stylesheet from Nmap.Org for more portable XML
          --no-stylesheet: Prevent associating of XSL stylesheet w/XML output
        MISC:
          -6: Enable IPv6 scanning
          -A: Enable OS detection, version detection, script scanning, and traceroute
          --datadir <dirname>: Specify custom Nmap data file location
          --send-eth/--send-ip: Send using raw ethernet frames or IP packets
          --privileged: Assume that the user is fully privileged
          --unprivileged: Assume the user lacks raw socket privileges
          -V: Print version number
          -h: Print this help summary page.
        EXAMPLES:
          nmap -v -A scanme.nmap.org
          nmap -v -sn 192.168.0.0/16 10.0.0.0/8
          nmap -v -iR 10000 -Pn -p 80
    """
    global terminal_manager

    try:
        if terminal_manager is None or not isinstance(terminal_manager, NmapSSHScanExecutor):
            terminal_manager = NmapSSHScanExecutor(**SSH_CONFIG)
        terminal_manager._ensure_ssh_connection()
        scan_result = terminal_manager.run_nmap_scan(
            target=target,
            nmap_args=nmap_args,
            encoding=encoding
        )

        if not scan_result.strip():
            return "Nmap扫描执行成功，但未返回有效结果（可能目标无响应或参数有误）"

        return scan_result

    except ValueError as ve:
        return f"参数错误：{str(ve)}"
    except Exception as e:
        error_msg = f"Nmap扫描执行失败：{str(e)}"
        terminal_manager = None
        return error_msg

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Nmap SSH Scanning Service (SSH configuration parameters passed via command line)")

    parser.add_argument(
        "--hostname",
        type=str,
        default="127.0.0.1",
        help="SSH target host address"
    )
    parser.add_argument(
        "--username",
        type=str,
        default="root",
        help="SSH Login Username"
    )
    parser.add_argument(
        "--password",
        type=str,
        default="12345678",
        help="SSH login password"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="SSH port number"
    )
    parser.add_argument(
        "--command-timeout",
        type=int,
        default=600,
        dest="command_timeout",
        help="SSH command execution timeout (seconds, default: 600)"
    )
    parser.add_argument(
        "--sftp-timeout",
        type=int,
        default=120,
        dest="sftp_timeout",
        help="SFTP operation timeout (seconds, default: 120)"
    )

    args = parser.parse_args()

    ssh_config_from_cli = {
        "hostname": args.hostname,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "command_timeout": args.command_timeout,
        "sftp_timeout": args.sftp_timeout
    }

    terminal_manager = NmapSSHScanExecutor(**ssh_config_from_cli)
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8001, path="/mcp")
