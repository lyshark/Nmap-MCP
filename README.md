# Nmap-MCP

This is an AI MCP server developed based on Nmap. After pre-configuring the login information of a Kali Linux host, it automates SSH login and executes Nmap scanning commands via the Paramiko module. The server is supported by FastMCP as the underlying MCP Server and utilizes Cherry Studio as the MCP Host tool for configuration management and integration with large models. It supports adapting to any large model to parse user natural language intents, organize scan results, and ultimately enables users to initiate network scans and receive clear structured feedback through simple conversational interactions without needing to master complex Nmap command syntax.

1、First, configure and install the third-party dependencies required for the project. You can directly execute the installation command using the pip package manager to deploy the paramiko module and FastMCP tool, laying the foundation for subsequent SSH remote connections and MCP server operation.

```bash
C:> pip install paramiko fastmcp
C:> pip show paramiko
Name: paramiko
Version: 4.0.0
Summary: SSH2 protocol library
Home-page:
Author:
Author-email: Jeff Forcier <jeff@bitprophet.org>
License-Expression: LGPL-2.1
Location: \Programs\Python\Python314\Lib\site-packages
Requires: bcrypt, cryptography, invoke, pynacl
Required-by:

C:> pip show fastmcp
Name: fastmcp
Version: 2.14.2
Summary: The fast, Pythonic way to build MCP servers and clients.
Home-page: https://gofastmcp.com
Author: Jeremiah Lowin
Author-email:
License-Expression: Apache-2.0
Location: Programs\Python\Python314\Lib\site-packages
Requires: authlib, cyclopts, exceptiongroup, httpx, jsonschema-path, mcp, openapi-pydantic, platformdirs, py-key-value-aio, pydantic, pydocket, pyperclip, python-dotenv, rich, uvicorn, websockets
Required-by:
```

2、It is necessary to ensure that the target Kali Linux host has enabled SSH service and supports remote login (SSH port connectivity can be verified in advance). When starting the AI MCP service in the future, simply enter the IP address, administrator login account and password, and corresponding SSH connection port of the Kali Linux host to complete the service startup and establish a valid connection.
```bash
C:> python NmapMCP.py --hostname 192.168.136.128 --username lyshark --password 123456789 --port 22

                   ┌──────────────────────────────────────────────────────────────────────────────┐
                   │                                                                              │
                   │                                                                              │
                   │                         ▄▀▀ ▄▀█ █▀▀ ▀█▀ █▀▄▀█ █▀▀ █▀█                        │
                   │                         █▀  █▀█ ▄▄█  █  █ ▀ █ █▄▄ █▀▀                        │
                   │                                                                              │
                   │                                                                              │
                   │                                FastMCP 2.14.2                                │
                   │                            https://gofastmcp.com                             │
                   │                                                                              │
                   │                    🖥   Server:      Kali Nmap MCP                             │                    
                   │                    🚀 Deploy free: https://fastmcp.cloud                     │
                   │                                                                              │
                   └──────────────────────────────────────────────────────────────────────────────┘
                   ┌──────────────────────────────────────────────────────────────────────────────┐
                   │                          ✨ FastMCP 3.0 is coming!                           │
                   │         Pin fastmcp<3 in production, then upgrade when you're ready.         │
                   └──────────────────────────────────────────────────────────────────────────────┘


[01/11/26 14:25:57] INFO     Starting MCP server 'Kali Nmap MCP' with transport 'streamable-http' on     server.py:2582
                             http://0.0.0.0:8001/mcp
```

Next, open the Cherry Studio tool, find and click the settings button, enter the MCP server configuration interface, enter the address and other related configuration information of the AI MCP server built earlier, confirm that there are no errors, and complete the entire configuration process of the MCP server.
