import tkinter as tk
from tkinter import scrolledtext
import threading
from scapy.all import sniff, stop_sniff

class NIDS_GUI:
    def __init__(self, master):
        self.master = master
        master.title("Detectr")

        self.start_button = tk.Button(master, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack()

        self.stop_button = tk.Button(master, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack()

        self.output_area = scrolledtext.ScrolledText(master, wrap=tk.WORD)
        self.output_area.pack(expand=True, fill='both')

        self.sniffing_thread = None
        self.is_sniffing = False

    def packet_callback(self, packet):
        summary = packet.summary()
        self.output_area.insert(tk.END, summary + '\n')
        self.output_area.see(tk.END)

    def start_sniffing(self):
        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.output_area.delete(1.0, tk.END)
        self.output_area.insert(tk.END, "Starting packet sniffing...\n")

        self.sniffing_thread = threading.Thread(target=self.packet_sniffer)
        self.sniffing_thread.start()

    def packet_sniffer(self):
        sniff(prn=self.packet_callback, store=0, stop_filter=lambda p: not self.is_sniffing)

    def stop_sniffing(self):
        self.is_sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.output_area.insert(tk.END, "Stopping packet sniffing...\n")
        stop_sniff()

def main():
    root = tk.Tk()
    app = NIDS_GUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
