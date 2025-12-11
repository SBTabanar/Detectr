import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import threading
import time
from scapy.all import sniff
from analyzer import PacketAnalyzer

# --- Configuration ---
ctk.set_appearance_mode("Light")  # Modern Light Theme
ctk.set_default_color_theme("dark-blue")  # Blue accent

class DetectrApp(ctk.CTk):
    """
    Main Application Class for Detectr Pro.
    Handles the GUI initialization, user interactions, and linking with the PacketAnalyzer.
    """
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("Detectr Pro - Network Intrusion Detection System")
        self.geometry("1100x750")
        self.minsize(900, 650)
        
        # Color Palette (High Contrast)
        self.colors = {
            "bg_main": "#E2E8F0",       # Darker gray background
            "bg_sidebar": "#FFFFFF",    # White sidebar
            "card_bg": "#FFFFFF",       # White cards
            "text_primary": "#020617",  # Deep black
            "text_secondary": "#475569",# Dark gray
            "accent": "#2563EB",        # Royal Blue
            "accent_hover": "#1D4ED8",  # Darker Blue
            "danger": "#DC2626",        # Red for stop
            "danger_hover": "#B91C1C",
            "success": "#059669",       # Green for status
            "badge_idle": "#CBD5E1",    # Slate 300
            "input_bg": "#F1F5F9"       # Slate 100
        }

        # Main Layout Configuration
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar (Navigation & Controls) ---
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0, fg_color=self.colors["bg_sidebar"])
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(6, weight=1)

        # Branding
        self.logo_label = ctk.CTkLabel(
            self.sidebar, 
            text="DETECTR PRO", 
            font=ctk.CTkFont(family="Roboto", size=28, weight="bold"),
            text_color=self.colors["accent"]
        )
        self.logo_label.grid(row=0, column=0, padx=30, pady=(40, 5))
        
        self.author_label = ctk.CTkLabel(
            self.sidebar, 
            text="Developed by SBTabanar", 
            font=ctk.CTkFont(family="Roboto", size=12, slant="italic"), 
            text_color=self.colors["text_secondary"]
        )
        self.author_label.grid(row=1, column=0, padx=30, pady=(0, 40))

        # Controls
        self.lbl_mode = ctk.CTkLabel(
            self.sidebar, 
            text="ANALYSIS MODE", 
            anchor="w",
            font=ctk.CTkFont(family="Roboto", size=11, weight="bold"),
            text_color=self.colors["text_secondary"]
        )
        self.lbl_mode.grid(row=2, column=0, padx=30, pady=(0, 5), sticky="w")
        
        self.option_mode = ctk.CTkOptionMenu(
            self.sidebar, 
            values=["Live Packet Sniffer", "Log Analysis"],
            fg_color=self.colors["bg_main"],
            text_color=self.colors["text_primary"],
            button_color=self.colors["accent"],
            button_hover_color=self.colors["accent_hover"],
            corner_radius=8,
            height=35
        )
        self.option_mode.grid(row=3, column=0, padx=30, pady=(0, 20), sticky="ew")

        # --- Settings Section ---
        self.lbl_settings = ctk.CTkLabel(
            self.sidebar,
            text="DETECTION THRESHOLDS",
            anchor="w",
            font=ctk.CTkFont(family="Roboto", size=11, weight="bold"),
            text_color=self.colors["text_secondary"]
        )
        self.lbl_settings.grid(row=4, column=0, padx=30, pady=(0, 5), sticky="w")

        # DoS Threshold Input
        self.entry_dos = ctk.CTkEntry(self.sidebar, placeholder_text="DoS Limit (pps)")
        self.entry_dos.insert(0, "100")
        self.entry_dos.grid(row=5, column=0, padx=30, pady=(0, 10), sticky="ew")
        
        # Scan Threshold Input
        self.entry_scan = ctk.CTkEntry(self.sidebar, placeholder_text="Scan Limit (ports)")
        self.entry_scan.insert(0, "15")
        self.entry_scan.grid(row=6, column=0, padx=30, pady=(0, 30), sticky="ew")

        # Buttons
        self.btn_run = ctk.CTkButton(
            self.sidebar, 
            text="START MONITORING", 
            font=ctk.CTkFont(family="Roboto", size=14, weight="bold"),
            fg_color=self.colors["accent"], 
            hover_color=self.colors["accent_hover"], 
            height=45,
            corner_radius=8,
            command=self.start_detection
        )
        self.btn_run.grid(row=7, column=0, padx=30, pady=10, sticky="ew")

        self.btn_stop = ctk.CTkButton(
            self.sidebar, 
            text="STOP SESSION", 
            font=ctk.CTkFont(family="Roboto", size=14, weight="bold"),
            fg_color=self.colors["bg_main"], 
            text_color=self.colors["danger"],
            hover_color=self.colors["badge_idle"], 
            height=45,
            corner_radius=8,
            state="disabled", 
            command=self.stop_detection
        )
        self.btn_stop.grid(row=8, column=0, padx=30, pady=10, sticky="ew")

        # --- Main Content Area ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=self.colors["bg_main"])
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_rowconfigure(2, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Header
        self.header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, padx=40, pady=(40, 20), sticky="ew")
        
        self.header_label = ctk.CTkLabel(
            self.header_frame, 
            text="Live Traffic Monitor", 
            font=ctk.CTkFont(family="Roboto", size=32, weight="bold"),
            text_color=self.colors["text_primary"]
        )
        self.header_label.pack(side="left")

        self.status_badge = ctk.CTkLabel(
            self.header_frame,
            text="● IDLE",
            font=ctk.CTkFont(family="Roboto", size=12, weight="bold"),
            text_color=self.colors["text_secondary"],
            fg_color=self.colors["badge_idle"],
            corner_radius=15,
            width=120,
            height=30
        )
        self.status_badge.pack(side="right")

        # Statistics / Info Cards
        self.stats_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.stats_frame.grid(row=1, column=0, padx=40, pady=(0, 20), sticky="ew")
        self.stats_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        self.stat_labels = {}
        for i, (key, label) in enumerate([("total", "Total Packets"), ("tcp", "TCP"), ("udp", "UDP"), ("arp", "ARP"), ("alerts", "Alerts")]):
            card = ctk.CTkFrame(self.stats_frame, fg_color=self.colors["card_bg"], corner_radius=10)
            card.grid(row=0, column=i, padx=5, sticky="ew")
            
            lbl_title = ctk.CTkLabel(card, text=label, font=("Roboto", 12), text_color=self.colors["text_secondary"])
            lbl_title.pack(pady=(10, 0))
            
            lbl_value = ctk.CTkLabel(card, text="0", font=("Roboto", 24, "bold"), text_color=self.colors["text_primary"])
            lbl_value.pack(pady=(0, 10))
            self.stat_labels[key] = lbl_value

        # Log / Console Area
        self.log_frame = ctk.CTkFrame(self.main_frame, fg_color=self.colors["card_bg"], corner_radius=12)
        self.log_frame.grid(row=2, column=0, sticky="nsew", padx=40, pady=(0, 40))
        self.log_frame.grid_rowconfigure(0, weight=0) # Title
        self.log_frame.grid_rowconfigure(1, weight=1) # Textbox
        self.log_frame.grid_columnconfigure(0, weight=1)

        self.log_label = ctk.CTkLabel(
            self.log_frame, 
            text="Security Alerts & System Logs", 
            font=ctk.CTkFont(family="Roboto", size=16, weight="bold"),
            text_color=self.colors["text_primary"]
        )
        self.log_label.grid(row=0, column=0, padx=20, pady=(15, 5), sticky="w")

        self.log_box = ctk.CTkTextbox(
            self.log_frame, 
            font=("Consolas", 13),
            text_color=self.colors["text_primary"],
            fg_color=self.colors["input_bg"],
            border_width=0,
            corner_radius=8
        )
        self.log_box.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        
        # State Initialization
        self.log("Detectr GUI initialized ready.")
        self.is_running = False
        self.analyzer = None
        self.sniff_thread = None

    def log(self, message):
        """
        Logs a message to the GUI console and a persistent log file.
        
        Args:
            message (str): The message string to log.
        """
        # Ensure thread safety for GUI updates
        timestamp = time.strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        
        # GUI Log
        self.log_box.insert("end", f"{formatted_message}\n")
        self.log_box.see("end")
        
        # File Log (Full Timestamp)
        full_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open("detectr.log", "a") as f:
                f.write(f"[{full_timestamp}] {message}\n")
        except Exception as e:
            print(f"Logging error: {e}")

    def update_stats(self):
        """Periodically update the statistics in the GUI."""
        if self.is_running and self.analyzer:
            stats = self.analyzer.get_stats()
            for key, label_widget in self.stat_labels.items():
                label_widget.configure(text=str(stats.get(key, 0)))
            
            # Schedule next update in 1s
            self.after(1000, self.update_stats)

    def start_detection(self):
        """
        Starts the packet sniffing process in a separate thread.
        Initializes the PacketAnalyzer and updates UI state.
        """
        if self.is_running: return

        self.is_running = True
        
        # Get Thresholds
        try:
            dos_limit = int(self.entry_dos.get())
            scan_limit = int(self.entry_scan.get())
        except ValueError:
            self.log("Invalid Input: Using default thresholds (100 pps, 15 ports)")
            dos_limit = 100
            scan_limit = 15

        # Update UI
        self.btn_run.configure(state="disabled", text="RUNNING...", fg_color=self.colors["bg_main"], text_color=self.colors["text_secondary"])
        self.btn_stop.configure(state="normal", fg_color=self.colors["danger"], text_color="white", hover_color=self.colors["danger_hover"])
        self.status_badge.configure(text="● MONITORING", text_color=self.colors["success"], fg_color="#D1FAE5")
        self.entry_dos.configure(state="disabled")
        self.entry_scan.configure(state="disabled")
        
        self.log(f"Starting Monitor (DoS>{dos_limit}pps, Scan>{scan_limit} ports)...")
        
        # Initialize Analyzer
        self.analyzer = PacketAnalyzer(self.log, dos_threshold=dos_limit, scan_threshold=scan_limit)
        
        # Start Stats Loop
        self.update_stats()

        # Run in background thread to keep GUI responsive
        self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniff_thread.start()

    def stop_detection(self):
        """
        Signals the sniffing thread to stop and updates the UI state.
        """
        self.is_running = False
        
        # Update UI (Optimistic)
        self.btn_run.configure(state="normal", text="START MONITORING", fg_color=self.colors["accent"], text_color="white")
        self.btn_stop.configure(state="disabled", fg_color=self.colors["bg_main"], text_color=self.colors["danger"])
        self.status_badge.configure(text="● IDLE", text_color=self.colors["text_secondary"], fg_color=self.colors["badge_idle"])
        self.entry_dos.configure(state="normal")
        self.entry_scan.configure(state="normal")
        
        self.log("Stopping Packet Sniffer...")

    def _sniff_packets(self):
        """
        Internal method to run scapy.sniff in a blocking manner (to be threaded).
        Catches exceptions (like missing Npcap) and logs them.
        """
        try:
            # Sniff packets. stop_filter checks self.is_running every packet
            sniff(prn=self.analyzer.process_packet, store=0, stop_filter=lambda x: not self.is_running)
        except Exception as e:
            self.log(f"Error: {e}")
            self.log("Ensure you have Npcap installed (Windows) or run as Root (Linux).")
        finally:
            self.is_running = False
            # Reset GUI state if thread ends naturally (e.g. error)
            # Use 'after' to update GUI from thread if strict thread safety needed, 
            # but CustomTkinter handles simple config updates well usually.
            self.btn_run.configure(state="normal", text="START MONITORING", fg_color=self.colors["accent"], text_color="white")
            self.btn_stop.configure(state="disabled", fg_color=self.colors["bg_main"], text_color=self.colors["danger"])
            self.status_badge.configure(text="● IDLE", text_color=self.colors["text_secondary"], fg_color=self.colors["badge_idle"])
            self.entry_dos.configure(state="normal")
            self.entry_scan.configure(state="normal")

def main():
    app = DetectrApp()
    app.mainloop()

if __name__ == "__main__":
    main()
