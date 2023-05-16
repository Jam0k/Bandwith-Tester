import subprocess
import threading
import tkinter as tk
from tkinter import ttk
import time 
from tkinter import filedialog
from datetime import datetime

class BandwidthTesterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Bandwidth Tester")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Variables
        self.serial_number = tk.StringVar(value='#00000')
        self.server_ip = tk.StringVar(value='127.0.0.1')
        self.port = tk.IntVar(value=5201)
        self.mode = tk.StringVar(value='Client')
        self.protocol = tk.StringVar(value='TCP')
        self.packet_size = tk.StringVar(value='1024')

        # Widgets
        ttk.Label(self, text="Serial Number:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(self, textvariable=self.serial_number).grid(row=0, column=1, sticky=tk.EW)

        ttk.Label(self, text="Server IP:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(self, textvariable=self.server_ip).grid(row=1, column=1, sticky=tk.EW)

        ttk.Label(self, text="Port:").grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(self, textvariable=self.port).grid(row=2, column=1, sticky=tk.EW)

        # Mode selection ComboBox
        ttk.Label(self, text="Mode:").grid(row=3, column=0, sticky=tk.W)
        mode_combobox = ttk.Combobox(self, textvariable=self.mode, values=["Client", "Server"], state="readonly")
        mode_combobox.grid(row=3, column=1, sticky=tk.EW)
        mode_combobox.current(0)

        # Add a trace to the mode variable
        self.mode.trace('w', self.on_mode_change)

        ttk.Label(self, text="Protocol:").grid(row=4, column=0, sticky=tk.W)
        protocol_combobox = ttk.Combobox(self, textvariable=self.protocol, values=["TCP", "UDP"], state="readonly")
        protocol_combobox.grid(row=4, column=1, sticky=tk.EW)
        protocol_combobox.current(0)

        ttk.Label(self, text="Packet Size:").grid(row=5, column=0, sticky=tk.W)
        self.packet_size_entry = ttk.Entry(self, textvariable=self.packet_size)
        self.packet_size_entry.grid(row=5, column=1, sticky=tk.EW)

        self.start_button = ttk.Button(self, text="Start Test", command=self.start_test)
        self.start_button.grid(row=6, column=0)

        self.stop_button = ttk.Button(self, text="Stop Test", command=self.stop_test, state=tk.DISABLED)
        self.stop_button.grid(row=6, column=1)

        self.clear_button = ttk.Button(self, text="Clear Log", command=self.clear_log)
        self.clear_button.grid(row=7, column=0)

        self.export_button = ttk.Button(self, text="Export Results", command=self.export_results, state=tk.DISABLED)
        self.export_button.grid(row=7, column=1)

        self.log_view = tk.Text(self, width=50, height=20)
        self.log_view.grid(row=8, columnspan=2, sticky=tk.EW)

        self.columnconfigure(1,
weight=1)

        self.test_process = None
        self.logs = []

    def on_mode_change(self, *args):
        """Handle the change of the mode variable."""
        if self.mode.get() == "Server":
            self.packet_size_entry.config(state='disabled')
        else:
            self.packet_size_entry.config(state='normal')

    def on_close(self):
        if self.test_process:
            self.stop_test()
        self.destroy()

    def start_test(self):
        if not self.test_process:
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.export_button.config(state=tk.DISABLED)
            self.clear_button.config(state=tk.DISABLED)
            self.logs = []  # Clear the previous logs

            test_thread = threading.Thread(target=self.start_test_thread, daemon=True)
            test_thread.start()

    def start_test_thread(self):
        server_ip = self.server_ip.get()
        port = self.port.get()
        mode = self.mode.get()
        protocol = self.protocol.get()
        packet_size = self.packet_size.get()
        serial_number = self.serial_number.get()

        command = ["iperf3"]
        if protocol == "UDP":
            command.append("-u")

        if mode == "Client":
            command.append("-l")
            command.append(packet_size)
            command.extend(["-c", server_ip, "-p", str(port)])
        else:
            command.extend(["-s", "-p", str(port)])

        self.test_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        for line in iter(self.test_process.stdout.readline, b''):
            log = line.decode("utf-8")
            self.log_view.insert(tk.END, log)
            self.log_view.see(tk.END)
            self.logs.append(log.strip())
            self.update_idletasks()

        # Append additional information to logs
        self.logs.append(datetime.now().strftime('Report Generated: %Y-%m-%d %H:%M:%S'))
        self.logs.append(f'Device Serial Number: {serial_number}')

        self.end_test()

    def end_test(self):
        if self.test_process:
            self.test_process = None

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.export_button.config(state=tk.NORMAL)
        self.clear_button.config(state=tk.NORMAL)

    def stop_test(self):
        if self.test_process:
            self.test_process.terminate()
            self.end_test()

    def clear_log(self):
        self.log_view.delete(1.0, tk.END)
        self.logs = []

    def export_results(self):
        if self.logs:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                                    filetypes=[("Text Files", "*.txt"), 
                                                                ("All Files", "*.*")])
            if file_path:
                with open(file_path, 'w') as f:
                    for log in self.logs:
                        f.write(f"{log}\n")
                self.export_button.config(state=tk.DISABLED)


if __name__ == '__main__':
    app = BandwidthTesterApp()
    app.mainloop()
