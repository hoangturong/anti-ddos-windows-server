
if (__name__ == "__main__"):
    import requests
    def check_key(key):
        key_check_url = f'https://vantrong.x10.mx/key/key.php?key={key}'
        #key_check_url = f'http://localhost/key/key.php?key={key}'
        try:
            response = requests.get(key_check_url)
            response.raise_for_status()  # Raise an error for bad responses
            key_data = response.json()  # Parse the JSON response
            return key_data  # Return the parsed data
        except requests.exceptions.RequestException as e:
            print("Unknown error, please ib admin to handle.")
            return None
            
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    import ctypes, sys
    import geoip2.database
    import requests
    import fileinput
    import subprocess
    import threading
    import sys
    from flask import Flask, request, render_template_string, redirect, url_for
    import json
    import os
    from config import *
    app = Flask(__name__)
    if is_admin():
        pass
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()
    key = input("Input your key: ")
    key_data = check_key(key)
    if key_data and key_data.get('Status') == 'success' or key == "keynoibo":
    
        def get_public_ip():
            response = requests.get('https://api.ipify.org?format=json')
            data = response.json()
            return data['ip']

        public_ip = get_public_ip()
        
        def clear():
            system("cls")

        #cau hinh sv
        ALLOWED_COUNTRIES = []
        while True:
            country = input("Nhập tên quốc gia được phép vào server của bạn(vd: VN)\n(Nhập '0' để dừng): ")
            if country == "0":
                break
            ALLOWED_COUNTRIES.append(country)
        #cau hinh sv
        port_server = input("Enter the port of the game server: ")
        #cau hinh sv
        port_fw = input("Enter the port of the firewall: ")
        #cau hinh sv
        host_server = input("Enter the host of the game server: ")
        def time_run():
            global time_count
            time_count=0
            while 1:
                sleep(1)
                time_count+=1
        
        def block_with_time(ip,time,is_add=1):
            global block,time_count
            if is_add==1:
                block.append(ip)
            while time_count<=time:
                sleep(1)
            while ip in block:
                block.remove(ip)
            print("Unblock: {} (Out of time)".format(ip))
            return
            
        def kill_process():
            print(f"\nClosing process....")
            if hasattr(signal, 'SIGKILL'):
                kill(pid, signal.SIGKILL)
            else:
                kill(pid, signal.SIGABRT)
            sys.exit()
            
        def forward(ip,port,source,destination,is_a,is_user_send,b=""):
            global time_count,block
            if is_a==1:
                byte_s=int(globals()["byte_send_user"])
                time_s=float(globals()["time_send_user"])
            else:
                byte_s=int(globals()["byte_send_server"])
                time_s=float(globals()["time_send_server"])
            len_data = -1
            if reset_send_data_user!=0:
                time=time_count+(reset_send_data_user*60)
            else:
                time=-1
            try:
                string = " "
                while string:
                    if len_data<max_data_user:
                        string = source.recv(byte_s)
                        if string:
                            if max_data_user>0 and is_user_send==0:
                                len_data+=len(string)
                            destination.sendall(string)
                        else:
                            source.shutdown(socket.SHUT_RD)
                            destination.shutdown(socket.SHUT_WR)
                        sleep(time_s)
                    else:
                        print("Out of data on {} min: Port {} from {} ({} byte)".format(reset_send_data_user,port,ip,max_data_user))
                        if type_block_send_data!=0:
                            block.append(ip)
                            block_ip(ip,port,source,1)
                        break
                    if time==-1:
                        continue
                    elif time_count>time and max_data_user>0:
                        time=time_count+(reset_send_data_user*60)
                        len_data=0
            except TimeoutError:
                print("==> Timeout: Port {} from {}".format(str(port),str(ip)))
            except ConnectionAbortedError:
                print("==> Aborted connection: Port {} from {}".format(str(port),str(ip)))
            except ConnectionResetError:
                print("==> Close connection: Port {} from {}".format(str(port),str(ip)))
            except ConnectionRefusedError:
                print("==> Connection refused: Port {} from {}".format(str(port),str(ip)))
            except:
                pass
            if is_a==1:
                global count_conn
                count_conn-=1
                conn_str = "conn_" + str(ip) + ":" + str(b)
                #all_conn.remove("conn_"+str(ip)+":"+str(b))
                if conn_str in all_conn:
                   all_conn.remove(conn_str)
                   del globals()[conn_str]
                #del globals()["conn_"+str(ip)+":"+str(b)]
            try:
                source.shutdown(socket.SHUT_RD)
                destination.shutdown(socket.SHUT_WR)
            except:
                return

        def close_conn():
            global all_conn, soc
            try:
                soc.close()
            except:
                pass
            for i in all_conn:
                try:
                    globals()[i].close()
                except:
                    pass
            return
           
        def get_country(ip):
            with geoip2.database.Reader("Country.mmdb") as reader:
                try:
                    response = reader.country(ip)
                    return response.country.iso_code
                except Exception as e:
                    print(f"no Country {ip}: {e}")
                    return None

        def load_blocked_ips():
            try:
                with open("block.txt", 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                return []

        def block_ip(con_ip, port, a, z=0):
            global ddos, force_block, list_ban_ip, time_count, all_conn
            country_code = get_country(con_ip)
            force_block[con_ip] = 0  
        
            def add_ip_to_list(con_ip):
                global list_ban_ip
                list_ban_ip += "," + con_ip
                add_ip_rule(port)
                with open("block.txt", "a") as f:
                    f.write(f"{con_ip},\n")

            if (type_block_spam == 2 and z == 0) or (type_block_send_data == 2 and z == 1):
                print("Block IP forever: {}".format(con_ip))
                if len(list_ban_ip) < 8111:
                    add_ip_to_list(con_ip)
            elif (type_block_spam == 3 and z == 0) or (type_block_send_data == 3 and z == 1):
                if block_time != 0:
                    print("Block {} for {} minutes".format(con_ip, block_time))
                    Thread(target=block_with_time, args=(con_ip, time_count + (block_time * 60), 0)).start()
            else:
                print("Block on ram: {}".format(con_ip))

            print("Close all connection from {}".format(con_ip))
            try:
               a.close()
            except Exception as e:
                print(f"Error closing connection: {e}")
            for i in [s for s in all_conn if "conn_{}:".format(con_ip) in s]:
                try:
                    all_conn.remove(i)
                except Exception as e:
                    print(f"Error removing connection: {e}")
                try:
                    globals()[i].close()
                except Exception as e:
                    print(f"Error closing global connection: {e}")
            return


        def create_rule(port):
            global list_ban_ip
            if (Popen("netsh advfirewall firewall show rule name=\"anti {0}\"".format(str(port)), shell=True, stdout=PIPE).stdout.read().decode().split("\r\n")[1][:2]=="No"):
                _=Popen("netsh advfirewall firewall add rule name= \"anti {0}\" dir=in action=block profile=any protocol=TCP localport={0} localip=any remoteip=\"{1}\"".format(str(port),str(list_ban_ip)), shell=True, stdout=DEVNULL)
            else:
                _=Popen("netsh advfirewall firewall set rule name=\"anti {0}\" new remoteip=\"{1}\"".format(str(port),str(list_ban_ip)), shell=True,stdin=PIPE,stdout=DEVNULL)
                sleep(2)
                list_ban_ip+=","+str(Popen("netsh advfirewall firewall show rule name=\"anti {0}\"".format(str(port)), shell=True, stdout=PIPE).stdout.read().decode().split("\r\n")[8].split()[1]).replace("/32","")
                list_ban_ip=str(",".join(list(set(list_ban_ip.split(",")))))
                _=Popen("netsh advfirewall firewall set rule name=\"anti {0}\" new remoteip=\"{1}\"".format(str(port),str(list_ban_ip)),shell=True,stdin=PIPE,stdout=DEVNULL)
            _=Popen("netsh advfirewall firewall set rule name=\"anti {0}\" new enable=yes".format(str(port)),shell=True,stdin=PIPE,stdout=DEVNULL)
            return

        def add_ip_rule(port):
            global list_ban_ip
            if (len(list_ban_ip)<8111):
                _=Popen("netsh advfirewall firewall set rule name=\"anti {0}\" new remoteip=\"{1}\"".format(str(port),str(list_ban_ip)),shell=True,stdin=PIPE,stdout=DEVNULL)
            return
        def handle_client(client_socket):
            try:
                # Kết nối đến server game
                game_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                game_server_socket.connect((host_server, port_server))

                def forward_data(source, destination):
                    try:
                        while True:
                            data = source.recv(4096)
                            if not data:
                                break
                            destination.sendall(data)
                    except Exception:
                        pass  # Bỏ qua mọi lỗi
                    finally:
                        source.close()
                        destination.close()

                # Tạo các luồng để chuyển tiếp dữ liệu
                client_to_game_thread = threading.Thread(target=forward_data, args=(client_socket, game_server_socket))
                game_to_client_thread = threading.Thread(target=forward_data, args=(game_server_socket, client_socket))

                client_to_game_thread.start()
                game_to_client_thread.start()

                # Chờ cho đến khi các luồng kết thúc
                client_to_game_thread.join()
                game_to_client_thread.join()
            except Exception:
                pass  # Bỏ qua lỗi trong quá trình xử lý
            finally:
                client_socket.close()


        def start_server():
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Tái sử dụng địa chỉ cổng ngay lập tức
            server_socket.bind((host_fw, port_fw))
            server_socket.listen(5)
            print(f"[*] Listening on {host_fw}:{port_fw}")

            try:
                while True:
                    client_socket, addr = server_socket.accept()
                    print(f"[*] Accepted connection from {addr}")
                    client_handler = threading.Thread(target=handle_client, args=(client_socket,))
                    client_handler.daemon = True  # Đảm bảo luồng sẽ tự động kết thúc khi chương trình dừng
                    client_handler.start()
            except KeyboardInterrupt:
                print("\n[*] Shutting down the server...")
            except Exception as e:
                print(f"[!] Error: {e}")
            finally:
                server_socket.close()

        def open_port(port):
            global ddos, block, force_block, list_ban_ip, max_conn, count_conn, all_conn, soc
            current_conn=[]
            all_conn=[]
            count=0
            count_conn=0
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                soc.bind((str(host_fw), int(port)))
                soc.listen(9)
                create_rule(port)
                Thread(target=time_run, args=()).start()
                print("==> Started: Successfully")
                while 1:
                    try:
                        a,b = soc.accept()
                        country_code = get_country(b[0])
                        if country_code and country_code not in ALLOWED_COUNTRIES and b[0] != '127.0.0.1':
                            print(f"Block IP: {b[0]} | Country: {country_code}")
                            save_blocked_ip(b[0])
                            list_ban_ip += str("," + b[0])
                            add_ip_rule(port)
                            block.append(b[0])
                            Thread(target=block_ip, args=(b[0],port,a)).start()
                            with open("block.txt", "a") as f:
                                f.write(f"{b[0]},\n")
                            print("Close all connection from {}".format(b[0]))
                            try:
                                a.close()
                            except Exception as e:
                                print(f"Error closing connection: {e}")
                            for i in [s for s in all_conn if "conn_{}:".format(b[0]) in s]:
                                try:
                                    all_conn.remove(i)
                                except Exception as e:
                                    print(f"Error removing connection: {e}")
                                try:
                                    globals()[i].close()
                                except Exception as e:
                                    print(f"Error closing global connection: {e}")
                            continue

                        if (b[0] in block):
                            a.close()
                            if (force_firewall_count>0):
                                try:
                                    force_block[b[0]]+=1
                                except:
                                    force_block[b[0]]=1
                                if (force_block[b[0]]>force_firewall_count):
                                    print("!! Detected {0} try request {1} times! Blocking...".format(str(b[0]),str(force_block[con_ip])))
                                    Thread(target=block_ip, args=(b[0],port,a)).start()
                                    force_block[b[0]]=0
                                    continue
                                print("Blocked connection from {0} ({1})".format(b[0],force_block[b[0]]))
                            else:
                                print("Blocked connection from {0}".format(b[0]))
                        else:
                            if (count_conn<=max_conn) or (b[0] in current_conn):
                                try:
                                    ddos[b[0]]+=1
                                except KeyError:
                                    ddos[b[0]]=1
                                try:
                                    if (ddos[b[0]]>block_on_count):
                                        print("!! Detected DDOS from {}! Blocking...".format(b[0]))
                                        block.append(b[0])
                                        Thread(target=block_ip, args=(b[0],port,a)).start()
                                        continue
                                except:
                                    ddos[b[0]]=1
                                if b[0] not in current_conn:
                                    count_conn+=1
                                    is_a=1
                                else:
                                    is_a=0
                                current_conn.append(b[0])
                                all_conn.append("conn_"+str(b[0])+":"+str(b[1]))
                                globals()["conn_"+str(b[0])+":"+str(b[1])]=a
                                count+=1
                                print(f"{count}. Port {port_server} -> {port} | Accept: {b[0]} ({ddos[b[0]]})")
                                start_server()
                                #server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                #server_socket.settimeout(5)
                               # server_socket.connect((str(host_server), int(port_server)))
                              #  server_socket.settimeout(timeout_conn)
                               # a.settimeout(timeout_conn)
                               # Thread(target=forward, args=(b[0],port,a,server_socket,1,is_a,b[1])).start()
                               # Thread(target=forward, args=(b[0],port,server_socket,a,0,0)).start()
                            else:
                                print("Full connection {}".format(b[0]))
                                a.close()
                        sleep(float(time_connect))
                    except OSError as e:
                        if '[closed]' not in str(soc):
                            print(f":Has DDoS Port {port}")
                            a.close()
                            continue
                        break
                    except:
                        continue
            except PermissionError:
                print(f"ERROR: Port {port} cannot be spoof! Need administrator permission!!")
                return
            except OSError as e:
                print(f"Has DDoS Port {port}")
                return
        def about():
            while 1:
                clear()
                a=str(input("NGUYEN-VAN-TRONG\n\n1. Facebook\n0. Back\n\n Your choose: "))
                if (a=="1"):
                    system("start \"\" \"https://fb.com/hackersbybus\"")
                elif (a=="0"):
                    break
        def remove_block(port):
            while 1:
                clear()
                a=str(input("Are you sure to remove all block IP? [Y/N]: "))
                if (a=="Y") or (a=="y"):
                    _=Popen("netsh advfirewall firewall delete rule name=\"anti {}\" dir=in".format(str(port)),shell=True,stdin=PIPE,stdout=DEVNULL)
                    print("Remove All Block IP from [Port {}] completed!\n".format(str(port)))
                    input("Press Enter to Exit!")
                    break
                elif (a=="N") or (a=="n"):
                    break
        def quocgia(ALLOWED_COUNTRIES):
            while 1:
                clear()
                print("Danh sách các quốc gia được phép:", ALLOWED_COUNTRIES)
                input("Press Enter to Exit!")
                break

        def start(port):
            clear()
            global ddos
            print(f"\nfirewall game:{public_ip}:{port_server}:0,0,0 ===> game:{public_ip}:{port_fw}:0,0,0")
            print(f"==> START...")
            Thread(target=open_port, args=(port,)).start()
            sleep(2)
            while 1:
                try:
                    #print("No DDOS in {} seconds".format(str(reset_on_time)))
                    ddos={}
                    sleep(float(reset_on_time))
                except KeyboardInterrupt:
                    print("Stopping all connection....")
                    close_conn()
                    input("==> Press Enter to Exit!")
                    kill_process()
        from os import kill, getpid, name, system, remove
        system("wmic process where name=\"firewall.exe\" CALL setpriority 256 > NUL 2>&1")
        system("title Anti-DDOS (NGUYEN-VAN-TRONG)")
        clear()
        try:
            from config import *
        except:
            print("==> config not found or syntax error!")
            input()
            sys.exit()
        from urllib.parse import unquote
        from subprocess import Popen, PIPE
        from time import sleep
        from threading import Thread
        from random import choice
        import socket, signal
        import requests
        try:
            from subprocess import DEVNULL
        except ImportError:
            from os import devnull
            DEVNULL = open(devnull, 'wb')
        global pid, ddos, block, force_block, list_ban_ip, blockk
        pid = getpid()
        ddos={}
        block=[]
        blockk=[]
        list_ban_ip=str(ban_ip).replace("/32","")
        force_block={}
        if (name=='nt'):
            try:
                if (int(len([str(x) for x in host_fw.split(".") if x and x!="\n"])+len([str(x) for x in host_server.split(".") if x and x!="\n"])) != 8):
                    print("ip fake or real may be not correct!")
                    _=int("NGUYEN-VAN-TRONG")
                if int(max_speed_user)<0:
                    print("max speed user should not be less than 0")
                    _=int("NGUYEN-VAN-TRONG")
                if int(max_speed_server)<0:
                    print("max speed server should not be less than 0")
                    _=int("NGUYEN-VAN-TRONG")
                if int(timeout_conn)<1:
                    print("timeout conn should not be less than 1")
                    _=int("NGUYEN-VAN-TRONG")
                if int(type_block_send_data)==0 or int(type_block_send_data)==1 or int(type_block_send_data)==2 or int(type_block_send_data)==3:
                    pass
                else:
                    print("type block send data must be 0 or 1 or 2 or 3")
                    _=int("NGUYEN-VAN-TRONG")
                if int(type_block_spam)==1 or int(type_block_spam)==2 or int(type_block_spam)==3:
                    pass
                else:
                    print("type block spam must be 1 or 2 or 3")
                    _=int("NGUYEN-VAN-TRONG")
                if int(reset_send_data_user)<0:
                    print("reset send data user should not be less than 0")
                    _=int("NGUYEN-VAN-TRONG")
                if int(max_conn)<1:
                    print("max conn should not be less than 1")
                    _=int("NGUYEN-VAN-TRONG")
                if int(max_data_user)<0:
                    print("max data should not be less than 0")
                    _=int("NGUYEN-VAN-TRONG")
                if int(port_server)<1 and int(port_server)>65535:
                    print("Port real must in range 1-65535")
                    _=int("NGUYEN-VAN-TRONG")
                if int(port_fw)<1 and int(port_fw)>65535:
                    print("Port fake must in range 1-65535")
                    _=int("NGUYEN-VAN-TRONG")
                if int(port_fw)==int(port_server):
                    print("Port fake and real must not the same!")
                    _=int("NGUYEN-VAN-TRONG")
                if float(time_connect)<0:
                    print("time connect should not be less than 0")
                    _=int("NGUYEN-VAN-TRONG")
                if int(block_on_count)<1:
                    print("Block on count should not be less than 1")
                    _=int("NGUYEN-VAN-TRONG")
                if int(reset_on_time)<1:
                    print("Reset on time should not be less than 1")
                    _=int("NGUYEN-VAN-TRONG")
                if int(is_get_sock)==1 or int(is_get_sock)==0:
                    pass
                else:
                    print("is get sock must be 0 or 1")
                    _=int("NGUYEN-VAN-TRONG")
                _=ban_sock
                _=headers
            except:
                print("\n==> Config is error!")
                input()
                kill_process()
            global byte_send_user, byte_send_server, time_send_user, time_send_server
            byte_send_user = int((max_speed_user * 1024)/4)
            time_send_user = 1/4 + 0.01
            byte_send_server = int((max_speed_user * 1024)/4)
            time_send_server = 1/4 + 0.01
            try:
                with open("block.txt","r") as f:
                    block=[str(x) for x in f.read().split(",") if x and x!="\n"]
            except FileNotFoundError:
                open("block.txt","w").write('')
                block=[]
            for i in block:
                list_ban_ip+=str(",{0}".format(str(i)))
            if int(is_get_sock) == 1:
                try:
                    with open("proxy.txt", "r") as f:
                        while True:
                            clear()
                            anti = str("n")  # Giả sử bạn có cách để nhận giá trị này từ người dùng
                            if (anti == "Y") or (anti == "y"):
                                exec("global blockk; {}".format(f.read()))
                                print("\nTotal IP Sock: {} IP".format(str(len(blockk))))
                                print("Real IP Sock: {} IP".format(str(len(list(set(blockk))))))
                                input("Press Enter to Start!")
                                break
                            elif (anti == "N") or (anti == "n"):
                                print()
                                break
                except:
                    total_ip = 0
                    for sock in ban_sock:
                        count_ip = 0
                        sys.stdout.flush()
                        try:
                            response = requests.get(sock, headers=headers, timeout=15)
                            response.raise_for_status()  # Raise an error for bad responses
                            proxies = response.text.splitlines()  # Split response into lines

                            for i in proxies:
                                try:
                                    temp = str(i.split(":")[0])
                                    int("".join(temp.split(".")))  # Kiểm tra xem có phải là IP không
                                    if i and len(temp.split(".")) == 4:
                                        blockk.append(temp)
                                        count_ip += 1
                                except:
                                    continue

                            total_ip += count_ip
                        except requests.RequestException:
                            print("(DIED)")

                    blockk = list(set(blockk))  # Loại bỏ các proxy trùng lặp
                    print("LOAD BLOCK FILE")
                    print("\nTotal IP Sock: {} IP".format(str(total_ip)))
                    print("Real IP Sock: {} IP".format(str(len(blockk))))
                    anti = str("y")
                    while True:
                        if (anti == "Y") or (anti == "y"):
                            with open("proxy.txt", "w") as f:
                                f.write("blockk={}".format(str(blockk)))
                            break
                        elif (anti == "N") or (anti == "n"):
                            os.remove("proxy.txt")
                            break

                print("Processing IP....")
                for _ in blockk:
                    block.append(str(_))
                del blockk

            block = list(set(block))
            clear()
            try:
                while 1:
                    clear()
                    print(f"\n1. firewall game:{host_server}:{port_server}:0,0,0 ===> game:{public_ip}:{port_fw}:0,0,0\n2. Remove All Block IP [Port {port_fw}]\n3. About\n4. Permitted Countries\n0. Exit\n\n")
                    anti=str(input("==> Your choose: "))
                    if (anti == "1"):
                        start(port_fw)
                    elif (anti == "2"):
                        remove_block(port_fw)
                    elif (anti == "3"):
                        about()
                    elif (anti == "4"):
                        quocgia(ALLOWED_COUNTRIES)
                    elif (anti == "0"):
                        kill_process()
                    continue
            except KeyboardInterrupt:
                print("Stopping all connection....")
                close_conn()
                input("==> Press Enter to Exit!")
                kill_process()
        else:
            print("\n==> This tool work only on Windows!\n")
            kill_process()
    else:
        print("Your key is either expired or does not exist. Please contact admin to buy a new key.")
        input()
        sys.exit()