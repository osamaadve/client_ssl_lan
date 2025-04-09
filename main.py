# -*- coding: utf-8 -*-
import socket
import json
import os
import argparse
import ssl

# --- استيراد من الملف المشترك ---
from common_utils import send_msg, recv_msg, recvall, DEFAULT_PORT, BUFFER_SIZE, DEFAULT_CERT_FILE

# --- Constants الخاصة بالعميل ---
DEFAULT_DOWNLOAD_DIR = "./client_downloads"

# --- Client Helper Functions ---
# (نفس الدوال display_listing, receive_file_from_server, browse_server_files, send_file [upload], send_message من الكود المدمج)
def display_listing(listing_data):
    path = listing_data.get('path', 'Unknown')
    items = listing_data.get('items', [])
    print(f"\n--- Server Path: '{path}' ---")
    if not items and path == ".": print("    (Directory is empty)")

    display_items = []
    is_root = (path == "." or os.path.normpath(path) == ".")
    if not is_root: display_items.append({'name': '.. (Go Up)', 'type': 'nav'})

    for item in items:
         display_items.append({
             'name': item.get('name', 'Unnamed'),
             'type': item.get('type', 'unknown'),
             'size': item.get('size', 0)
         })

    if not display_items: print("   (Directory seems empty)"); return display_items

    print(" Idx | Type     | Size       | Name")
    print("-----|----------|------------|------------------------------")
    for i, item in enumerate(display_items):
        name, type_str, size_bytes = item['name'], item['type'].upper(), item['size']
        type_disp = f"<{type_str}>" if type_str in ['DIR','NAV'] else type_str.capitalize() if type_str != '???' else '???'
        size_str = ""
        if type_str == 'FILE':
             if size_bytes < 1024: size_str = f"{size_bytes} B"
             elif size_bytes < 1024**2: size_str = f"{size_bytes/1024:.1f} KB"
             elif size_bytes < 1024**3: size_str = f"{size_bytes/1024**2:.1f} MB"
             else: size_str = f"{size_bytes/1024**3:.1f} GB"
        elif type_str not in ['DIR','NAV']: size_str = f"{size_bytes} B"
        print(f" {i:<3} | {type_disp:<8} | {size_str:<10} | {name}")
    print("-------------------------------------------------------------")
    return display_items


def receive_file_from_server(ssl_sock, filename, filesize, save_dir):
    os.makedirs(save_dir, exist_ok=True)
    base, ext = os.path.splitext(filename)
    counter = 1
    save_path = os.path.join(save_dir, filename)
    while os.path.exists(save_path):
        save_path = os.path.join(save_dir, f"{base}_{counter}{ext}")
        counter += 1

    print(f"[*] Receiving file: '{os.path.basename(save_path)}' ({filesize} bytes)")
    print(f"[*] Saving to: {save_path}")

    bytes_received = 0
    try:
        with open(save_path, 'wb') as f:
            while bytes_received < filesize:
                file_chunk_result = recv_msg(ssl_sock) # Get chunk from server
                if isinstance(file_chunk_result, MemoryError): raise file_chunk_result
                if file_chunk_result is None: raise ConnectionAbortedError("Download aborted by server or network.")
                file_chunk_decrypted = file_chunk_result

                f.write(file_chunk_decrypted)
                bytes_received += len(file_chunk_decrypted)
                percent = (bytes_received / filesize) * 100 if filesize > 0 else 100
                print(f"    Rcvd {bytes_received}/{filesize} bytes ({percent:.1f}%)", end='\r')
        print(f"\n[+] File '{os.path.basename(save_path)}' downloaded successfully.")
        return True
    except (IOError, MemoryError, ConnectionAbortedError) as e:
        print(f"\n[!] Error downloading '{os.path.basename(save_path)}': {e}")
        if os.path.exists(save_path) and 'bytes_received' in locals() and bytes_received < filesize:
             try: os.remove(save_path); print(f"  -> Removed incomplete download: {save_path}")
             except OSError as e_rem: print(f"[!] Error removing incomplete {save_path}: {e_rem}")
        return False
    except Exception as e: print(f"\n[!] Unexpected error during download: {e}"); return False


def browse_server_files(ssl_sock, download_dir):
    current_remote_path = "."
    while True:
        list_req = {'type': 'list_dir', 'path': current_remote_path}
        print(f"\n[*] Requesting listing for server path: '{current_remote_path}'...")
        if not send_msg(ssl_sock, json.dumps(list_req).encode('utf-8')): print("[!] Failed list request."); return

        response_data_result = recv_msg(ssl_sock)
        if isinstance(response_data_result, MemoryError): print(f"[!] Memory error receiving listing: {response_data_result}."); return
        if response_data_result is None: print("[!] Connection closed receiving listing."); return
        response_data = response_data_result

        try:
            response = json.loads(response_data.decode('utf-8'))
            response_type = response.get('type')

            if response_type == 'dir_listing':
                displayed_items = display_listing(response)
                current_remote_path = response.get('path', current_remote_path)

                if not displayed_items:
                     sel = input("Enter 'b' back to main, 'q' quit browse: ").strip().lower()
                     if sel == 'b': current_remote_path = os.path.dirname(current_remote_path) if current_remote_path != "." else "."
                     elif sel == 'q': break
                     else: continue

                while True: # Inner loop for user selection
                    selection = input("Enter index, 'r' refresh, 'q' quit browse: ").strip().lower()
                    if selection == 'q': return
                    if selection == 'r': break # Break inner loop to refresh list

                    try:
                        idx = int(selection)
                        if 0 <= idx < len(displayed_items):
                            item = displayed_items[idx]
                            item_type, item_name = item['type'], item['name']

                            if item_type == 'dir':
                                current_remote_path = os.path.normpath(os.path.join(current_remote_path, item_name))
                                break # Break inner loop to list new dir
                            elif item_type == 'nav': # Go Up
                                current_remote_path = os.path.dirname(current_remote_path)
                                if not current_remote_path : current_remote_path = "."
                                break # Break inner loop to list parent dir
                            elif item_type == 'file':
                                if input(f"Download '{item_name}'? (y/n): ").lower() == 'y':
                                    file_rel_path = os.path.normpath(os.path.join(current_remote_path, item_name))
                                    download_req = {'type': 'download_file', 'filepath': file_rel_path}
                                    print(f"[*] Requesting download: {file_rel_path}")
                                    if not send_msg(ssl_sock, json.dumps(download_req).encode('utf-8')): print("[!] Failed download request.")
                                    else:
                                        print("[*] Waiting for server download response...")
                                        file_resp_data_result = recv_msg(ssl_sock)
                                        if isinstance(file_resp_data_result, MemoryError): print(f"[!] Memory error on download response: {file_resp_data_result}")
                                        elif file_resp_data_result is None: print("[!] Connection closed waiting for download response.")
                                        else:
                                             file_resp_data = file_resp_data_result
                                             try:
                                                 file_resp = json.loads(file_resp_data.decode('utf-8'))
                                                 if file_resp.get('type') == 'file_info':
                                                     receive_file_from_server(ssl_sock, file_resp.get('filename'), file_resp.get('filesize'), download_dir)
                                                 elif file_resp.get('type') == 'error': print(f"[!] Server DL error: {file_resp.get('message')}")
                                                 else: print(f"[!] Unexpected DL response: {file_resp.get('type')}")
                                             except (json.JSONDecodeError, UnicodeDecodeError) as e: print(f"[!] Invalid DL response: {e}")
                                    break # Break inner loop to refresh list after download attempt
                                else: print("   Download cancelled."); continue # Continue inner loop
                            else: print(f"[!] Unsupported type: {item_type}"); continue
                        else: print("[!] Invalid index.")
                    except ValueError: print("[!] Invalid input.")

            elif response_type == 'error':
                print(f"[!] Server error: {response.get('message')}")
                if input("Enter 'b' back, 'q' quit browse: ").lower() == 'b':
                    parent = os.path.dirname(current_remote_path); parent = "." if not parent else parent
                    if parent != current_remote_path: current_remote_path = parent; continue
                    else: print("[!] Cannot go back further."); break
                else: break # Quit browse
            else: print(f"[!] Unexpected server response type: {response_type}"); break

        except (json.JSONDecodeError, UnicodeDecodeError) as e: print(f"[!] Failed decode server response: {e}"); break
        except Exception as e: print(f"[!] Unexpected error processing response: {e}"); break


def upload_file(ssl_sock, filepath):
    """يرسل ملفًا (Upload) إلى الخادم."""
    if not os.path.isfile(filepath): print(f"[!] File not found: '{filepath}'"); return False
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    file_info = { 'type': 'file_info', 'filename': filename, 'filesize': filesize }
    print(f"[*] Sending UPLOAD info: {filename} ({filesize} bytes)")
    if not send_msg(ssl_sock, json.dumps(file_info).encode('utf-8')): print("[!] Failed send UPLOAD info."); return False

    print("[*] Waiting for server UPLOAD confirmation...")
    conf_data_result = recv_msg(ssl_sock)
    if isinstance(conf_data_result, MemoryError): print(f"[!] Mem error on UPLOAD conf: {conf_data_result}"); return False
    if conf_data_result is None: print("[!] No UPLOAD confirmation."); return False
    conf_data = conf_data_result

    try:
        conf = json.loads(conf_data.decode('utf-8'))
        if conf.get('status') != 'ready_for_upload': print(f"[!] Server not ready for UPLOAD: {conf}"); return False
        server_fname = conf.get('filename')
        print(f"[*] Server ready for UPLOAD as '{server_fname}'. Sending data...")
    except (json.JSONDecodeError, UnicodeDecodeError, KeyError, AttributeError) as e: print(f"[!] Invalid UPLOAD conf: {e}"); return False

    bytes_sent = 0
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk: break
                if not send_msg(ssl_sock, chunk): print(f"\n[!] Failed send UPLOAD chunk at {bytes_sent}."); raise ConnectionAbortedError("Failed send chunk")
                bytes_sent += len(chunk)
                print(f"    Sent UPLOAD {bytes_sent}/{filesize} bytes", end='\r')
        print(f"\n[*] UPLOAD data sent ({bytes_sent} bytes). Waiting final confirm...")

        final_conf_res = recv_msg(ssl_sock)
        if isinstance(final_conf_res, MemoryError): print(f"[!] Mem error on final UPLOAD conf: {final_conf_res}"); return False
        if final_conf_res is None: print("[!] No final UPLOAD confirmation."); return False
        final_conf_data = final_conf_res

        try:
             final_conf = json.loads(final_conf_data.decode('utf-8'))
             if final_conf.get('status') == 'upload_received' and final_conf.get('filename') == server_fname:
                 print(f"[+] Server confirmed UPLOAD of '{server_fname}'. Success!"); return True
             else: print(f"[!] Unexpected final UPLOAD conf: {final_conf}"); return False
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError, AttributeError) as e: print(f"[!] Invalid final UPLOAD conf: {e}"); return False
    except (IOError, ConnectionAbortedError) as e: print(f"\n[!] Error during UPLOAD transmission: {e}"); return False
    except Exception as e: print(f"\n[!] Unexpected error during UPLOAD: {e}"); return False


def send_message(ssl_sock, text_message):
    """يرسل رسالة نصية بسيطة."""
    message = { 'type': 'message', 'payload': text_message }
    print(f"[*] Sending message: '{text_message}'")
    if send_msg(ssl_sock, json.dumps(message).encode('utf-8')): print("[+] Message sent."); return True
    else: print("[!] Failed to send message."); return False


# --- Client Main Logic ---
# (نفس الدالة run_client من الكود المدمج، مع التأكد من استخدام الدوال المستوردة وتغيير اسم send_file إلى upload_file)
def run_client(server_ip, port, client_name, server_cert, download_dir):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False # WARNING: Less secure for LAN
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        print(f"[*] Loading server CA cert: {server_cert}")
        context.load_verify_locations(cafile=server_cert)
        print("[+] Server CA cert loaded.")
    except (ssl.SSLError, FileNotFoundError, Exception) as e: print(f"[!] Error loading server CA: {e}"); return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_client_socket = None
    try:
        print(f"[*] Connecting to {server_ip}:{port}...")
        client_socket.connect((server_ip, port))
        print("[*] TCP connected. Wrapping SSL/TLS...")
        ssl_client_socket = context.wrap_socket(client_socket, server_hostname=server_ip)
        print("[+] SSL/TLS connection established.")

        identity_msg = {'type': 'identity', 'name': client_name}
        if not send_msg(ssl_client_socket, json.dumps(identity_msg).encode('utf-8')):
             print("[!] Failed send identity. Disconnecting."); return

        while True:
            print("\n--- Client Main Menu ---")
            print("  1. Send text message")
            print("  2. Upload file to server")
            print("  3. Browse/Download from server")
            print("  4. Disconnect")
            choice = input("Enter choice (1/2/3/4): ").strip()

            if choice == '1':
                msg = input("Enter message: ")
                if msg: send_message(ssl_client_socket, msg)
                else: print("[!] Message empty.")
            elif choice == '2': # UPLOAD
                fpath = input("Enter full path to UPLOAD: ").strip().strip('\'"')
                if fpath: upload_file(ssl_client_socket, fpath) # Call upload_file
                else: print("[!] File path empty.")
            elif choice == '3': # Browse/Download
                browse_server_files(ssl_client_socket, download_dir)
            elif choice == '4':
                 print("[*] Sending disconnect...")
                 send_msg(ssl_client_socket, json.dumps({'type': 'disconnect'}).encode('utf-8'))
                 break
            else: print("[!] Invalid choice.")

    except ssl.SSLCertVerificationError as e: print(f"[!] SSL Cert Verify Error: {e}")
    except ssl.SSLError as e: print(f"[!] SSL Error: {e}")
    except ConnectionRefusedError: print(f"[!] Connection refused. Server down/wrong IP/port?")
    except socket.timeout: print("[!] Connection timed out.")
    except socket.gaierror: print(f"[!] Error resolving server: {server_ip}")
    except KeyboardInterrupt:
         print("\n[!] Disconnecting (Ctrl+C).")
    if ssl_client_socket:
        try: send_msg(ssl_client_socket, json.dumps({'type':'disconnect'}).encode('utf-8'))
        except Exception as e:
            print(f"[!] Unexpected client error: {e}")
        finally:
            print("[*] Closing client connection.")
        if ssl_client_socket:
            try: ssl_client_socket.shutdown(socket.SHUT_RDWR)
            except:
                pass; ssl_client_socket.close()
        elif client_socket: client_socket.close()


# --- Main Execution Block for Client ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Secure Client for File/Message Sharing (SSL/TLS)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show defaults
    )
    parser.add_argument('-s', '--server', required=True, help="Server IP address or hostname")
    parser.add_argument('--name', default=socket.gethostname(), help="Client name identifier")
    parser.add_argument('--cacert', default=DEFAULT_CERT_FILE, help="Path to server's CA certificate file for verification")
    parser.add_argument('--download-dir', default=DEFAULT_DOWNLOAD_DIR, help="Local directory to save downloaded files")
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help="Port number")

    args = parser.parse_args()

    if not os.path.exists(args.cacert):
         print(f"[!] Error: Server CA cert file not found: {args.cacert}")
         print("[!] Copy server.crt from the server or specify path with --cacert.")
         exit(1)

    try: os.makedirs(args.download_dir, exist_ok=True)
    except OSError as e: print(f"[!] Cannot create download dir '{args.download_dir}': {e}"); exit(1)

    run_client(args.server, args.port, args.name, args.cacert, args.download_dir)