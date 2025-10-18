# scanner_app.py
import sys
import os
import json
import csv
import time
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QComboBox, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame, QMessageBox
)
from PyQt6.QtCore import QThread, Qt, pyqtSlot

import matplotlib
from matplotlib.figure import Figure
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas

from scan_logic import ScanWorker

matplotlib.use('QtAgg')

class MatplotlibCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi, tight_layout=True)
        self.axes = self.fig.add_subplot(111)
        super(MatplotlibCanvas, self).__init__(self.fig)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scan_results = []
        self.scan_thread = None
        self.scan_worker = None
        self.setup_ui()
        self.setWindowTitle("Port Scanner")
        self.setGeometry(100, 100, 1400, 800)
        self.setStyleSheet("""
            QWidget { background-color: #f0f2f5; color: #333; font-family: 'Segoe UI'; font-size: 10pt; }
            QLabel#titleLabel { font-size: 14pt; font-weight: bold; }
            QFrame#metricFrame { background-color: white; border: 1px solid #ddd; border-radius: 5px; }
            QLabel#metricValueLabel { font-size: 24pt; font-weight: bold; color: #007bff; }
            QPushButton { padding: 8px; border: 1px solid #ccc; border-radius: 4px; background-color: #fff; }
            QPushButton:hover { background-color: #e9e9e9; }
            QPushButton#startButton { background-color: #28a745; color: white; font-weight: bold; }
            QPushButton#startButton:hover { background-color: #218838; }
            QPushButton#stopButton { background-color: #dc3545; color: white; font-weight: bold; }
            QPushButton#stopButton:hover { background-color: #c82333; }
            QLineEdit, QTextEdit, QComboBox { padding: 5px; border: 1px solid #ccc; border-radius: 4px; background-color: white; }
            QTableWidget { background-color: white; border: 1px solid #ddd; }
            QHeaderView::section { background-color: #f8f9fa; padding: 4px; border: 1px solid #ddd; font-weight: bold; }
        """)

    def setup_ui(self):
        main_layout = QHBoxLayout()
        main_container = QWidget()
        main_container.setLayout(main_layout)
        self.setCentralWidget(main_container)

        controls_panel = QFrame()
        controls_panel.setFixedWidth(350)
        self.controls_layout = QVBoxLayout(controls_panel)
        self.controls_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        controls_title = QLabel("Controls"); controls_title.setObjectName("titleLabel")
        self.controls_layout.addWidget(controls_title)

        self.controls_layout.addWidget(QLabel("Mode:"))
        self.mode_combo = QComboBox(); self.mode_combo.addItems(["Single", "Bulk (Range / CIDR)"])
        self.controls_layout.addWidget(self.mode_combo)

        self.single_mode_widget = QWidget()
        single_layout = QVBoxLayout(self.single_mode_widget)
        single_layout.setContentsMargins(0, 10, 0, 0)
        single_layout.addWidget(QLabel("Target (IP or domain):"))
        self.target_input = QLineEdit(); self.target_input.setPlaceholderText("e.g., google.com")
        single_layout.addWidget(self.target_input)

        self.bulk_mode_widget = QWidget()
        bulk_layout = QVBoxLayout(self.bulk_mode_widget)
        bulk_layout.setContentsMargins(0, 10, 0, 0)
        bulk_layout.addWidget(QLabel("IP Range (e.g., 192.168.1.1-192.168.1.254):"))
        self.ip_range_input = QLineEdit(); self.ip_range_input.setPlaceholderText("192.168.1.1-192.168.1.10")
        bulk_layout.addWidget(self.ip_range_input)
        bulk_layout.addWidget(QLabel("CIDR (one per line):"))
        self.cidr_input = QTextEdit(); self.cidr_input.setPlaceholderText("192.168.0.0/24\n10.0.0.0/28")
        self.cidr_input.setFixedHeight(80)
        bulk_layout.addWidget(self.cidr_input)

        self.controls_layout.addWidget(self.single_mode_widget)
        self.controls_layout.addWidget(self.bulk_mode_widget)
        self.bulk_mode_widget.hide()
        self.mode_combo.currentIndexChanged.connect(self.update_control_widgets)

        self.controls_layout.addWidget(QLabel("Ports (leave empty for default):"))
        self.ports_input = QLineEdit(); self.ports_input.setPlaceholderText("80, 443, 22, 8000-8010")
        self.controls_layout.addWidget(self.ports_input)

        self.controls_layout.addWidget(QLabel("Protocol:"))
        self.protocol_combo = QComboBox(); self.protocol_combo.addItems(["TCP", "UDP", "Both"])
        self.controls_layout.addWidget(self.protocol_combo)

        buttons_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start"); self.start_btn.setObjectName("startButton")
        self.stop_btn = QPushButton("Stop"); self.stop_btn.setObjectName("stopButton")
        self.stop_btn.setEnabled(False)
        buttons_layout.addWidget(self.start_btn)
        buttons_layout.addWidget(self.stop_btn)
        self.controls_layout.addLayout(buttons_layout)

        export_layout = QHBoxLayout()
        self.export_csv_btn = QPushButton("Export CSV")
        self.export_json_btn = QPushButton("Export JSON")
        export_layout.addWidget(self.export_csv_btn)
        export_layout.addWidget(self.export_json_btn)
        self.controls_layout.addLayout(export_layout)

        self.controls_layout.addStretch()

        results_panel = QWidget()
        results_layout = QVBoxLayout(results_panel)
        stats_layout = QHBoxLayout()

        def create_metric_box(label_text, value_color):
            box = QFrame(); box.setObjectName("metricFrame")
            layout = QVBoxLayout(box)
            label = QLabel(label_text); label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            value = QLabel("0"); value.setObjectName("metricValueLabel"); value.setStyleSheet(f"color: {value_color};")
            value.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(label); layout.addWidget(value)
            return box, value

        open_box, self.open_ports_label = create_metric_box("Open Ports", "#28a745")
        closed_box, self.closed_ports_label = create_metric_box("Closed Ports", "#dc3545")
        progress_box = QFrame(); progress_box.setObjectName("metricFrame")
        progress_layout = QVBoxLayout(progress_box)
        progress_layout.addWidget(QLabel("Progress"), alignment=Qt.AlignmentFlag.AlignCenter)
        self.progress_bar = QProgressBar(); self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)

        stats_layout.addWidget(open_box); stats_layout.addWidget(closed_box); stats_layout.addWidget(progress_box)
        results_layout.addLayout(stats_layout)

        bottom_results_layout = QHBoxLayout()
        results_group = QWidget()
        results_group_layout = QVBoxLayout(results_group)
        results_group_layout.setContentsMargins(0, 0, 0, 0)
        results_table_label = QLabel("Scan Results"); results_table_label.setObjectName("titleLabel")
        results_group_layout.addWidget(results_table_label)
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)

        # *** THAY ĐỔI 1: Đổi tên cột cuối cùng ***
        self.results_table.setHorizontalHeaderLabels(["Target", "Open Ports", "Closed Ports", "Elapsed Time (s)"])

        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        # Thay đổi kích thước cột cuối cho phù hợp
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        results_group_layout.addWidget(self.results_table)

        bottom_results_layout.addWidget(results_group, stretch=2)

        right_side_panel = QWidget()
        right_side_layout = QVBoxLayout(right_side_panel)

        chart_label = QLabel("Top 10 Open Ports"); chart_label.setObjectName("titleLabel")
        right_side_layout.addWidget(chart_label)
        self.chart = MatplotlibCanvas(self)
        right_side_layout.addWidget(self.chart, stretch=1)

        log_label = QLabel("Real-time Log"); log_label.setObjectName("titleLabel")
        right_side_layout.addWidget(log_label)
        self.log_output = QTextEdit(); self.log_output.setReadOnly(True)
        self.log_output.setPlaceholderText("Scan events will appear here...")
        right_side_layout.addWidget(self.log_output, stretch=1)

        bottom_results_layout.addWidget(right_side_panel, stretch=1)
        results_layout.addLayout(bottom_results_layout)

        main_layout.addWidget(controls_panel)
        main_layout.addWidget(results_panel)

        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.export_csv_btn.clicked.connect(self.export_to_csv)
        self.export_json_btn.clicked.connect(self.export_to_json)

        self.results_table.cellDoubleClicked.connect(self.show_full_cell_content)

    # ... (Các hàm update_control_widgets, start_scan, stop_scan, on_scan_finished, reset_ui_state giữ nguyên) ...
    def update_control_widgets(self, index):
        if index == 0: self.single_mode_widget.show(); self.bulk_mode_widget.hide()
        else: self.single_mode_widget.hide(); self.bulk_mode_widget.show()

    def start_scan(self):
        self.reset_ui_state()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        config = {
            "mode": self.mode_combo.currentText().lower().split(" ")[0],
            "target": self.target_input.text(),
            "ip_range": self.ip_range_input.text(),
            "cidr": self.cidr_input.toPlainText(),
            "ports": self.ports_input.text(),
            "protocol": self.protocol_combo.currentText()
        }

        self.scan_thread = QThread()
        self.scan_worker = ScanWorker(config)
        self.scan_worker.moveToThread(self.scan_thread)

        self.scan_thread.started.connect(self.scan_worker.run_scan)
        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.finished.connect(self.scan_worker.deleteLater)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.finished.connect(self.on_scan_finished)

        self.scan_worker.result_ready.connect(self.update_with_result)
        self.scan_worker.log_message.connect(self.add_log_message)
        self.scan_worker.progress_update.connect(self.update_progress)

        self.scan_thread.start()

    def stop_scan(self):
        if self.scan_worker:
            self.scan_worker.stop()
        self.stop_btn.setEnabled(False)

    def on_scan_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.add_log_message("Scan process has concluded.")

    def reset_ui_state(self):
        self.scan_results.clear()
        self.results_table.setRowCount(0)
        self.open_ports_label.setText("0")
        self.closed_ports_label.setText("0")
        self.progress_bar.setValue(0)
        self.log_output.clear()
        self.chart.axes.clear()
        self.chart.draw()
        self.add_log_message("UI reset. Ready for new scan.")


    @pyqtSlot(str)
    def add_log_message(self, message):
        timestamp = datetime.now().strftime("%I:%M:%S %p")
        self.log_output.append(f"[{timestamp}] {message}")

    @pyqtSlot(int, int)
    def update_progress(self, completed, total):
        if total > 0:
            percentage = int((completed / total) * 100)
            self.progress_bar.setValue(percentage)

    @pyqtSlot(dict)
    def update_with_result(self, result):
        # Lưu trữ kết quả (không cần thêm timestamp ở đây nữa)
        self.scan_results.append(result)

        log_line = (f"Target: {result['target']} | "
                    f"Open: {result.get('open_ports', [])} | "
                    f"Closed: {result.get('closed_ports', [])}")
        self.add_log_message(log_line)

        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        target_item = QTableWidgetItem(result['target'])

        open_ports_str = ", ".join(result['open_ports'])
        open_ports_item = QTableWidgetItem(open_ports_str)

        closed_ports_str = ", ".join(result['closed_ports'])
        closed_ports_item = QTableWidgetItem(closed_ports_str)

        # *** THAY ĐỔI 2: Lấy elapsed_time từ kết quả backend và hiển thị ***
        elapsed_time = result.get('elapsed_time', 0.0)
        elapsed_item = QTableWidgetItem(f"{elapsed_time:.2f}s") # Format thành chuỗi có 2 chữ số thập phân

        open_ports_item.setToolTip(open_ports_str)
        closed_ports_item.setToolTip(closed_ports_str)

        self.results_table.setItem(row, 0, target_item)
        self.results_table.setItem(row, 1, open_ports_item)
        self.results_table.setItem(row, 2, closed_ports_item)
        self.results_table.setItem(row, 3, elapsed_item) # <<< Đặt item thời gian trôi qua

        total_open = int(self.open_ports_label.text()) + len(result['open_ports'])
        total_closed = int(self.closed_ports_label.text()) + len(result['closed_ports'])
        self.open_ports_label.setText(str(total_open))
        self.closed_ports_label.setText(str(total_closed))

        self.update_chart()

    @pyqtSlot(int, int)
    def show_full_cell_content(self, row, column):
        # ... (Hàm show_full_cell_content giữ nguyên) ...
        if column not in [1, 2]: return
        item = self.results_table.item(row, column)
        if not item or not item.text(): return
        full_text = item.toolTip()
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Full Port List")
        msg_box.setText(f"Ports for {self.results_table.item(row, 0).text()}:")
        msg_box.setInformativeText(full_text)
        msg_box.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        msg_box.exec()

    def update_chart(self):
        # ... (Hàm update_chart giữ nguyên) ...
        top_ports = {}
        for res in self.scan_results:
            for port in res.get('open_ports', []):
                top_ports[port] = top_ports.get(port, 0) + 1

        if not top_ports: return

        sorted_ports = sorted(top_ports.items(), key=lambda item: item[1], reverse=True)[:10]
        labels = [item[0] for item in sorted_ports]
        counts = [item[1] for item in sorted_ports]

        self.chart.axes.clear()
        self.chart.axes.bar(labels, counts, color='#28a745')
        self.chart.axes.set_title("Top Open Ports")
        self.chart.axes.set_ylabel("Count")
        self.chart.fig.autofmt_xdate(rotation=45)
        self.chart.draw()


    def export_to_csv(self):
        if not self.scan_results:
            self.add_log_message("No data to export.")
            return
        path = os.path.join("Success_Results", f"export_{int(time.time())}.csv")
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                # *** THAY ĐỔI 3: Xóa 'timestamp' khỏi header ***
                writer = csv.writer(f)
                writer.writerow(["target", "open_ports", "closed_ports", "banners"])
                for res in self.scan_results:
                    writer.writerow([
                        res.get('target', ''),
                        ",".join(res.get('open_ports', [])),
                        ",".join(res.get('closed_ports', [])),
                        json.dumps(res.get('banners', {}))
                        # Không cần lấy timestamp nữa
                    ])
            log_msg = f"Successfully exported to {path}"
            self.add_log_message(log_msg)
            QMessageBox.information(self, "Export Successful", f"Data exported successfully to:\n{path}")
        except Exception as e:
            error_msg = f"Error exporting to CSV: {e}"
            self.add_log_message(error_msg)
            QMessageBox.critical(self, "Export Failed", f"Could not export data to CSV:\n{e}")

    def export_to_json(self):
        if not self.scan_results:
            self.add_log_message("No data to export.")
            return
        path = os.path.join("Success_Results", f"export_{int(time.time())}.json")
        try:
            # *** THAY ĐỔI 4: Tạo bản sao dữ liệu không có elapsed_time trước khi dump ***
            results_to_export = []
            for res in self.scan_results:
                # Tạo bản sao và xóa key 'elapsed_time' nếu nó tồn tại
                res_copy = res.copy()
                res_copy.pop('elapsed_time', None)
                results_to_export.append(res_copy)

            with open(path, "w", encoding="utf-8") as f:
                json.dump(results_to_export, f, indent=2, ensure_ascii=False)
            log_msg = f"Successfully exported to {path}"
            self.add_log_message(log_msg)
            QMessageBox.information(self, "Export Successful", f"Data exported successfully to:\n{path}")
        except Exception as e:
            error_msg = f"Error exporting to JSON: {e}"
            self.add_log_message(error_msg)
            QMessageBox.critical(self, "Export Failed", f"Could not export data to JSON:\n{e}")

    def closeEvent(self, event):
        # ... (Hàm closeEvent giữ nguyên) ...
        if self.scan_thread and self.scan_thread.isRunning():
            self.stop_scan()
            self.scan_thread.quit()
            self.scan_thread.wait()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())