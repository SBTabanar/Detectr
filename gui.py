import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import threading
import time
from scapy.all import sniff
from analyzer import PacketAnalyzer

# --- Configuration ---
ctk.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

class DetectrApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("Detectr Pro")
        self.geometry("1000x700")
        self.minsize(800, 600)
        
        # Grid Layout (Sidebar + Main Content)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar (Controls) ---
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar, text="DETECTR", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.lbl_mode = ctk.CTkLabel(self.sidebar, text="Analysis Mode:", anchor="w")
        self.lbl_mode.grid(row=1, column=0, padx=20, pady=(20, 0), sticky="w")
        
        self.option_mode = ctk.CTkOptionMenu(self.sidebar, values=["Live Packet Sniffer", "Log Analysis"])
        self.option_mode.grid(row=2, column=0, padx=20, pady=10)

        self.btn_stop = ctk.CTkButton(self.sidebar, text="STOP", fg_color="#555", state="disabled", command=self.stop_detection)
        self.btn_stop.grid(row=3, column=0, padx=20, pady=10)

        self.btn_run = ctk.CTkButton(self.sidebar, text="START DETECTION", fg_color="#e74c3c", hover_color="#c0392b", command=self.start_detection)
        self.btn_run.grid(row=4, column=0, padx=20, pady=10)

        # --- Main Content Area ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Header
        self.header_label = ctk.CTkLabel(self.main_frame, text="Dashboard", font=ctk.CTkFont(size=20))
        self.header_label.grid(row=0, column=0, padx=10, pady=(0, 10), sticky="w")

        # Preview / Results Panel
        self.preview_frame = ctk.CTkFrame(self.main_frame, fg_color="#2b2b2b")
        self.preview_frame.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, 20))
        
        self.lbl_status = ctk.CTkLabel(self.preview_frame, text="System Idle", text_color="gray", font=("Consolas", 14))
        self.lbl_status.place(relx=0.5, rely=0.5, anchor="center")

        # Console / Logs
        self.log_box = ctk.CTkTextbox(self.main_frame, height=150, font=("Consolas", 12))
        self.log_box.grid(row=2, column=0, sticky="ew")
        
        self.log("Detectr GUI initialized.")
        self.is_running = False
        self.analyzer = None
        self.sniff_thread = None

    def log(self, message):
        # Ensure thread safety for GUI updates
        self.log_box.insert("end", f">> {message}\n")
        self.log_box.see("end")

    def start_detection(self):
        if self.is_running: return

        self.is_running = True
        self.btn_run.configure(state="disabled", text="RUNNING...")
        self.btn_stop.configure(state="normal", fg_color="#e74c3c")
        self.lbl_status.configure(text="MONITORING NETWORK TRAFFIC...", text_color="#2ecc71")
        
        self.log("Initializing Packet Sniffer...")
        
        # Initialize Analyzer
        self.analyzer = PacketAnalyzer(self.log)
        
        # Run in background thread to keep GUI responsive
        self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniff_thread.start()

    def stop_detection(self):
        self.is_running = False
        self.btn_run.configure(state="normal", text="START DETECTION")
        self.btn_stop.configure(state="disabled", fg_color="#555")
        self.lbl_status.configure(text="System Idle", text_color="gray")
        self.log("Stopping Sniffer...")

    def _sniff_packets(self):
        try:
            # Sniff packets. stop_filter checks self.is_running every packet
            sniff(prn=self.analyzer.process_packet, store=0, stop_filter=lambda x: not self.is_running)
        except Exception as e:
            self.log(f"Error: {e}")
            self.log("Ensure you have Npcap installed (Windows) or run as Root (Linux).")
        finally:
            self.is_running = False
            # Reset GUI state if thread ends naturally
            self.btn_run.configure(state="normal", text="START DETECTION")
            self.btn_stop.configure(state="disabled", fg_color="#555")

def main():
    app = DetectrApp()
    app.mainloop()

if __name__ == "__main__":
    main()
