# backend.py
import os
import json
import time
import socket
import logging
import concurrent.futures
import csv
from ipaddress import ip_address, ip_network
from PyQt6.QtCore import QObject, pyqtSignal


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scanner_pyqt_backend")
PORT_TIMEOUT = 2
os.makedirs('Success_Results', exist_ok=True)
SUMMARY_JSON = os.path.join('Success_Results', 'summary.jsonl')

def DATA_SAVE(result, filename):
    try:
        with open(os.path.join('Success_Results', filename), "a", encoding="utf-8") as save:
            save.write(f'{result}\n')
    except Exception as e:
        logger.error(f"Failed to write to {filename}: {e}")

def SAVE_SUMMARY(obj):
    try:
        with open(SUMMARY_JSON, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.error(f"Failed to write summary: {e}")

def parse_ports(ports_str):
    if not ports_str: return []
    parts = [p.strip() for p in ports_str.split(",") if p.strip()]
    ports_set = set()
    for part in parts:
        if "-" in part:
            try:
                a, b = map(int, part.split("-", 1))
                if a > b: a, b = b, a
                ports_set.update(range(max(1, a), min(65535, b) + 1))
            except Exception: continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535: ports_set.add(p)
            except Exception: continue
    return sorted(list(ports_set))

# *** HÀM GRAB_BANNER ĐÃ ĐƯỢC CẢI TIẾN ***
def grab_banner(host, port, timeout=1.5): # Tăng nhẹ timeout
    banner = ""
    probe = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            # Xác định và chuẩn bị probe nếu cần
            if port in [80, 8080, 8000]: # HTTP
                # Gửi HEAD thay vì GET để chỉ lấy header, nhanh hơn
                probe = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
            # elif port == 25: # SMTP - Thường gửi banner ngay, nhưng có thể thử HELO
            #     probe = b"HELO test.com\r\n"
            # Bạn có thể thêm các probe cho dịch vụ khác ở đây (FTP, etc.)

            # Gửi probe nếu có
            if probe:
                try:
                    s.sendall(probe)
                except socket.error as e:
                    logger.debug(f"Error sending probe to {host}:{port}: {e}")
                    # Vẫn tiếp tục thử nhận dữ liệu

            # Cố gắng nhận dữ liệu (có thể là banner ban đầu hoặc phản hồi probe)
            try:
                # Tăng bộ đệm và thử đọc nhiều lần hơn một chút
                s.settimeout(timeout / 2) # Chia sẻ thời gian chờ
                data_parts = []
                while True: # Đọc cho đến khi timeout hoặc không còn dữ liệu
                    chunk = s.recv(1024) # Đọc từng phần nhỏ
                    if not chunk:
                        break
                    data_parts.append(chunk)
                    # Một số dịch vụ gửi xong là dừng, không cần đợi timeout
                    if len(data_parts) > 4: # Giới hạn số lần đọc để tránh vòng lặp vô hạn nếu dịch vụ liên tục gửi
                         break
                if data_parts:
                    banner = b"".join(data_parts).decode(errors='ignore')

            except socket.timeout:
                 logger.debug(f"Timeout receiving banner/response from {host}:{port}")
                 if not banner: # Nếu chưa nhận được gì cả thì mới là timeout thực sự
                      return "" # Trả về rỗng nếu timeout
            except socket.error as e:
                 logger.debug(f"Socket error receiving banner from {host}:{port}: {e}")

            # Làm sạch banner (loại bỏ ký tự không in được, giữ lại xuống dòng, tab)
            if banner:
                cleaned_banner = ''.join(c for c in banner if c.isprintable() or c in '\r\n\t ')
                banner = cleaned_banner.strip()

    except socket.timeout:
        logger.debug(f"Timeout connecting to {host}:{port} for banner grab.")
    except ConnectionRefusedError:
        logger.debug(f"Connection refused by {host}:{port} for banner grab.")
    except OSError as e:
        logger.debug(f"OS error grabbing banner from {host}:{port}: {e}")
    except Exception as e:
        # Ghi log lỗi không mong muốn để dễ sửa lỗi
        logger.error(f"Unexpected error grabbing banner from {host}:{port}: {type(e).__name__} - {e}")

    return banner

def IP_Ranger(start_ip, end_ip):
    try:
        start, end = int(ip_address(start_ip)), int(ip_address(end_ip))
        if end < start: start, end = end, start
        return [str(ip_address(ip)) for ip in range(start, end + 1)]
    except ValueError:
        return []

class ScanWorker(QObject):
    finished = pyqtSignal()
    result_ready = pyqtSignal(dict)
    log_message = pyqtSignal(str)
    progress_update = pyqtSignal(int, int)

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.is_cancelled = False
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=200)

    def run_scan(self):
        ports_ = parse_ports(self.config["ports"])
        if not ports_:
            ports_ = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 8080]

        targets = self._get_targets()
        if not targets:
            self.log_message.emit("Error: No valid targets found.")
            self.finished.emit()
            return

        self.log_message.emit(f"Starting scan on {len(targets)} targets...")

        protocol = self.config["protocol"].lower()
        scan_futures = []
        for target in targets:
            if self.is_cancelled: break
            if protocol in ("tcp", "both"):
                scan_futures.append(self.executor.submit(self._scan_tcp, target, ports_))
            if protocol in ("udp", "both"):
                scan_futures.append(self.executor.submit(self._scan_udp, target, ports_))

        completed = 0
        total_tasks = len(scan_futures)
        for future in concurrent.futures.as_completed(scan_futures):
            if self.is_cancelled: break
            try:
                result = future.result()
                if result: self.result_ready.emit(result)
            except Exception as e:
                self.log_message.emit(f"Error processing a task: {e}")

            completed += 1
            self.progress_update.emit(completed, total_tasks)

        self.log_message.emit("Scan finished.")
        self.finished.emit()

    def _get_targets(self):
        targets = set()
        mode = self.config["mode"]
        if mode == "single":
            if t := self.config["target"].strip(): targets.add(t)
        elif mode == "bulk":
            if ip_range := self.config["ip_range"].strip():
                try:
                    start, end = ip_range.split("-", 1)
                    targets.update(IP_Ranger(start.strip(), end.strip()))
                except Exception as e:
                    self.log_message.emit(f"Invalid IP Range format: {e}")
            if cidr_value := self.config["cidr"].strip():
                for line in cidr_value.splitlines():
                    if not line.strip(): continue
                    try:
                        net = ip_network(line.strip(), strict=False)
                        targets.update(str(ip) for ip in (net.hosts() or net))
                    except ValueError as e:
                        self.log_message.emit(f"Invalid CIDR format: {e}")
        return sorted(list(targets))

    def _scan_tcp(self, host, ports):
        start_time = time.time()
        if self.is_cancelled: return None
        result = {"target": host, "open_ports": [], "closed_ports": [], "banners": {}}

        def _connect(port):
            try:
                socket.create_connection((host, port), timeout=PORT_TIMEOUT).close()
                return port, True
            except (socket.timeout, ConnectionRefusedError, OSError):
                return port, False

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(_connect, p): p for p in ports}
            banner_futures = {} # Lưu future lấy banner riêng

            for future in concurrent.futures.as_completed(future_to_port):
                if self.is_cancelled: break
                port, status = future.result()
                label = f"{port}/tcp"
                if status:
                    result["open_ports"].append(label)
                    DATA_SAVE(f'{host}:{label}', 'Live_Data.txt')
                    # Đưa việc lấy banner vào executor để không làm chậm vòng lặp chính
                    banner_futures[executor.submit(grab_banner, host, port)] = label
                else:
                    result["closed_ports"].append(label)

            # Thu thập kết quả banner sau khi quét cổng xong
            for future in concurrent.futures.as_completed(banner_futures):
                 if self.is_cancelled: break
                 label = banner_futures[future]
                 try:
                     banner = future.result()
                     if banner:
                         result["banners"][label] = banner
                 except Exception as e:
                      logger.error(f"Error getting banner result for {label}: {e}")


        if result["open_ports"]: DATA_SAVE(host, 'Live_IP.txt')
        else: DATA_SAVE(host, 'RIP_Data.txt')
        SAVE_SUMMARY({"ts": int(start_time), "target": host, **result})

        end_time = time.time()
        elapsed_time = round(end_time - start_time, 2)
        result["elapsed_time"] = elapsed_time
        return result

    def _scan_udp(self, host, ports):
        start_time = time.time()
        if self.is_cancelled: return None
        result = {"target": host, "open_ports": [], "closed_ports": []}
        for port in ports:
            result["closed_ports"].append(f"{port}/udp")

        self.log_message.emit(f"UDP scan for {host} is illustrative. All ports marked as closed.")
        DATA_SAVE(host, 'RIP_Data.txt')
        SAVE_SUMMARY({"ts": int(start_time), "target": host, **result})

        end_time = time.time()
        elapsed_time = round(end_time - start_time, 2)
        result["elapsed_time"] = elapsed_time
        return result

    def stop(self):
        self.log_message.emit("Stop signal received. Finishing current tasks...")
        self.is_cancelled = True
        self.executor.shutdown(wait=False, cancel_futures=True)
