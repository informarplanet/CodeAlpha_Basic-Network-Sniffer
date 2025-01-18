#!/usr/bin/env python3
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from scapy.all import *
from datetime import datetime
import sys
import logging
from collections import defaultdict
import binascii
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
import os
import json
import time
from typing import Dict, List, Tuple, Any
from itertools import zip_longest
import tempfile
from PIL import Image, ImageTk
import re

class PacketCaptureGUI:
    def __init__(self):
        # Initialize main window
        self.root = ctk.CTk()
        self.root.title("Network Packet Analyzer")
        self.root.geometry("1200x800")
        
        # Initialize variables
        self.is_capturing = False
        self.packet_list = []
        self.status_var = tk.StringVar()
        self.selected_iface = tk.StringVar()
        self.filter_text = tk.StringVar()
        self.statistics = defaultdict(int)
        self.capture_thread = None
        
        # Initialize captured files storage
        self.captured_files = {
            'images': [],
            'documents': [],
            'audio': [],
            'videos': []
        }
        
        # Content type mappings with magic numbers/signatures
        self.content_types = {
            'image/jpeg': {'category': 'images', 'ext': '.jpg', 'signature': [b'\xFF\xD8\xFF']},
            'image/png': {'category': 'images', 'ext': '.png', 'signature': [b'\x89PNG\r\n']},
            'image/gif': {'category': 'images', 'ext': '.gif', 'signature': [b'GIF87a', b'GIF89a']},
            'image/bmp': {'category': 'images', 'ext': '.bmp', 'signature': [b'BM']},
            'image/webp': {'category': 'images', 'ext': '.webp', 'signature': [b'RIFF', b'WEBP']},
            'image/x-icon': {'category': 'images', 'ext': '.ico', 'signature': [b'\x00\x00\x01\x00']},
            'image/svg+xml': {'category': 'images', 'ext': '.svg', 'signature': [b'<?xml', b'<svg']},
            
            'application/pdf': {'category': 'documents', 'ext': '.pdf', 'signature': [b'%PDF']},
            'application/msword': {'category': 'documents', 'ext': '.doc', 'signature': [b'\xD0\xCF\x11\xE0']},
            'application/vnd.openxmlformats-officedocument': {'category': 'documents', 'ext': '.docx', 'signature': [b'PK\x03\x04']},
            'application/vnd.ms-excel': {'category': 'documents', 'ext': '.xls', 'signature': [b'\xD0\xCF\x11\xE0']},
            'application/vnd.ms-powerpoint': {'category': 'documents', 'ext': '.ppt', 'signature': [b'\xD0\xCF\x11\xE0']},
            
            'audio/mpeg': {'category': 'audio', 'ext': '.mp3', 'signature': [b'ID3', b'\xFF\xFB']},
            'audio/wav': {'category': 'audio', 'ext': '.wav', 'signature': [b'RIFF', b'WAVE']},
            'audio/ogg': {'category': 'audio', 'ext': '.ogg', 'signature': [b'OggS']},
            
            'video/mp4': {'category': 'videos', 'ext': '.mp4', 'signature': [b'\x00\x00\x00\x20ftyp']},
            'video/webm': {'category': 'videos', 'ext': '.webm', 'signature': [b'\x1A\x45\xDF\xA3']},
            'video/x-msvideo': {'category': 'videos', 'ext': '.avi', 'signature': [b'RIFF', b'AVI ']}
        }
        
        # Create GUI elements
        self.create_gui_elements()
        self.create_context_menu()
        self.update_interface_list()
        
    def create_gui_elements(self):
        # Main container with padding
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        
        # Top toolbar frame with darker theme
        toolbar = ctk.CTkFrame(self.root, fg_color="#2b2b2b")
        toolbar.grid(row=0, column=0, padx=10, pady=5, sticky="ew")
        
        # Interface selection with better visibility
        iface_label = ctk.CTkLabel(toolbar, text="Network Interface:", 
                                font=ctk.CTkFont(size=13, weight="bold"))
        iface_label.pack(side="left", padx=5)
        
        self.iface_combo = ctk.CTkOptionMenu(toolbar, 
                                          variable=self.selected_iface,
                                          width=200,
                                          font=ctk.CTkFont(size=13),
                                          fg_color="#333333",
                                          button_color="#404040",
                                          button_hover_color="#505050")
        self.iface_combo.pack(side="left", padx=5)
        
        # Control buttons with modern styling
        self.start_btn = ctk.CTkButton(toolbar, text="Start Capture",
                                    command=self.start_capture,
                                    font=ctk.CTkFont(size=13),
                                    fg_color="#2ecc71",
                                    hover_color="#27ae60",
                                    text_color="#000000")
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ctk.CTkButton(toolbar, text="Stop Capture",
                                   command=self.stop_capture,
                                   font=ctk.CTkFont(size=13),
                                   fg_color="#e74c3c",
                                   hover_color="#c0392b",
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        
        # Filter section
        filter_label = ctk.CTkLabel(toolbar, text="Filter:",
                                 font=ctk.CTkFont(size=13, weight="bold"))
        filter_label.pack(side="left", padx=5)
        
        self.filter_entry = ctk.CTkEntry(toolbar, 
                                     textvariable=self.filter_text,
                                     width=200,
                                     font=ctk.CTkFont(size=13),
                                     fg_color="#333333")
        self.filter_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        filter_btn = ctk.CTkButton(toolbar, text="Apply Filter",
                                command=self.apply_filter,
                                font=ctk.CTkFont(size=13))
        filter_btn.pack(side="left", padx=5)
        
        # TCP Flags filter
        self.tcp_flags_var = tk.StringVar(value="ALL")
        tcp_flags_label = ctk.CTkLabel(toolbar, text="TCP Flags:")
        tcp_flags_label.pack(side="left", padx=5)
        tcp_flags_combo = ttk.Combobox(toolbar, textvariable=self.tcp_flags_var,
                                     values=["ALL", "SYN", "ACK", "FIN", "RST", "PSH", "URG"])
        tcp_flags_combo.pack(side="left", padx=5)
        tcp_flags_combo.bind('<<ComboboxSelected>>', self.apply_filter)
        
        # Right side buttons
        right_buttons = ctk.CTkFrame(toolbar, fg_color="#2b2b2b")
        right_buttons.pack(side="right", padx=5)
        
        clear_btn = ctk.CTkButton(right_buttons, text="Clear",
                               command=self.clear_capture,
                               font=ctk.CTkFont(size=13),
                               fg_color="#e67e22",
                               hover_color="#d35400")
        clear_btn.pack(side="right", padx=5)
        
        save_btn = ctk.CTkButton(right_buttons, text="Save",
                              command=self.save_capture,
                              font=ctk.CTkFont(size=13))
        save_btn.pack(side="right", padx=5)
        
        stats_btn = ctk.CTkButton(right_buttons, text="Statistics",
                               command=self.show_statistics,
                               font=ctk.CTkFont(size=13))
        stats_btn.pack(side="right", padx=5)
        
        captured_content_btn = ctk.CTkButton(right_buttons, text="Captured Content",
                               command=self.show_captured_content,
                               font=ctk.CTkFont(size=13))
        captured_content_btn.pack(side="right", padx=5)
        
        # Main content area with packet list and details
        content = ctk.CTkFrame(self.root, fg_color="#1a1a1a")
        content.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=3)
        content.grid_rowconfigure(1, weight=2)
        
        # Packet list frame
        list_frame = ctk.CTkFrame(content, fg_color="#1a1a1a")
        list_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        
        # Custom style for treeview with better visibility
        style = ttk.Style()
        style.configure("Treeview",
                       background="#000000",  # Pure black background
                       foreground="#00ff00",  # Bright green text for better visibility
                       fieldbackground="#000000",
                       borderwidth=0,
                       font=('Segoe UI', 11))
        style.configure("Treeview.Heading",
                       background="#000000",  # Black header background
                       foreground="#00ffff",  # Cyan header text
                       borderwidth=1,
                       relief="flat",
                       font=('Segoe UI', 11, 'bold'))
        style.map("Treeview",
                 background=[("selected", "#003366")],  # Dark blue selection
                 foreground=[("selected", "#ffffff")])  # White text for selected items
        
        # Packet list with headers
        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.packet_tree = ttk.Treeview(list_frame, columns=columns,
                                      show="headings", style="Treeview",
                                      height=15)  # Fixed height to avoid scrollbar
        
        # Configure columns with better visibility
        self.packet_tree.column("No.", width=80, anchor="center", stretch=False)
        self.packet_tree.column("Time", width=160, anchor="center", stretch=False)
        self.packet_tree.column("Source", width=200, anchor="center", stretch=False)
        self.packet_tree.column("Destination", width=200, anchor="center", stretch=False)
        self.packet_tree.column("Protocol", width=100, anchor="center", stretch=False)
        self.packet_tree.column("Length", width=80, anchor="center", stretch=False)
        self.packet_tree.column("Info", width=400, anchor="w", stretch=True)
        
        # Configure column headings with better visibility
        for col in columns:
            self.packet_tree.heading(col, text=col)
        
        # Add vertical scrollbar
        self.vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.packet_tree.yview)
        self.vsb.pack(side="right", fill="y")
        
        # Add horizontal scrollbar
        self.hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.packet_tree.xview)
        self.hsb.pack(side="bottom", fill="x")
        
        # Configure the treeview
        self.packet_tree.configure(yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)
        self.packet_tree.pack(fill="both", expand=True)
        
        # Bind right-click event to packet tree
        self.packet_tree.bind("<Button-3>", self.show_context_menu)
        
        # Bottom panes for details and hex
        bottom_frame = ctk.CTkFrame(content, fg_color="#000000")  # Black background
        bottom_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_columnconfigure(1, weight=1)
        bottom_frame.grid_rowconfigure(0, weight=1)
        
        # Packet details with better visibility
        details_frame = ctk.CTkFrame(bottom_frame, fg_color="#000000")  # Black background
        details_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        
        details_label = ctk.CTkLabel(details_frame, 
                                  text="Packet Details",
                                  font=ctk.CTkFont(size=13, weight="bold"),
                                  text_color="#00ffff")  # Cyan text for header
        details_label.pack(side="top", padx=5, pady=2)
        
        # Details tree with black background
        style.configure("Details.Treeview",
                      background="#000000",  # Black background
                      foreground="#00ff00",  # Bright green text
                      fieldbackground="#000000",
                      font=('Segoe UI', 11))
        style.configure("Details.Treeview.Heading",
                      background="#000000",
                      foreground="#00ffff",
                      borderwidth=0)
        style.map("Details.Treeview",
                 background=[("selected", "#003366")],
                 foreground=[("selected", "#ffffff")])
        
        self.details_tree = ttk.Treeview(details_frame, 
                                       show="tree",
                                       style="Details.Treeview")
        details_scroll = ctk.CTkScrollbar(details_frame,
                                      command=self.details_tree.yview,
                                      fg_color="#000000",  # Black scrollbar
                                      button_color="#333333",
                                      button_hover_color="#444444")
        
        self.details_tree.configure(yscrollcommand=details_scroll.set)
        self.details_tree.pack(side="left", fill="both", expand=True)
        details_scroll.pack(side="right", fill="y")
        
        # Hex view with black background
        hex_frame = ctk.CTkFrame(bottom_frame, fg_color="#000000")  # Black background
        hex_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        
        hex_label = ctk.CTkLabel(hex_frame, 
                              text="Hex Dump",
                              font=ctk.CTkFont(size=13, weight="bold"),
                              text_color="#00ffff")  # Cyan text for header
        hex_label.pack(side="top", padx=5, pady=2)
        
        self.hex_view = ctk.CTkTextbox(hex_frame,
                                    font=ctk.CTkFont(family="Consolas", size=12),
                                    fg_color="#000000",  # Black background
                                    text_color="#00ff00",  # Bright green text
                                    wrap="none")
        self.hex_view.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready to capture packets")
        status_bar = ctk.CTkLabel(self.root,
                               textvariable=self.status_var,
                               font=ctk.CTkFont(size=12))
        status_bar.grid(row=2, column=0, padx=10, pady=(0, 5), sticky="ew")
        
        # Bind selection event
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)
        
    def create_context_menu(self):
        """Create right-click context menu for packet list"""
        # Create main context menu
        self.context_menu = tk.Menu(self.root, tearoff=0, bg='black', fg='#00ff00')
        
        # Add menu items
        self.context_menu.add_command(label="Show Full Headers", command=self.show_full_headers)
        self.context_menu.add_command(label="Show Hex View", command=self.show_hex_view)
        self.context_menu.add_separator()
        
        # Content analysis submenu
        self.content_menu = tk.Menu(self.context_menu, tearoff=0, bg='black', fg='#00ff00')
        self.context_menu.add_cascade(label="Content Analysis", menu=self.content_menu)
        
        # Add content analysis options
        self.content_menu.add_command(label="Show as Text", command=lambda: self.show_content("text"))
        self.content_menu.add_command(label="Show as Image", command=lambda: self.show_content("image"))
        self.content_menu.add_command(label="Show as Audio", command=lambda: self.show_content("audio"))
        self.content_menu.add_command(label="Show as Document", command=lambda: self.show_content("document"))
        self.content_menu.add_command(label="Show as Hex", command=lambda: self.show_content("hex"))
        
        # Export submenu
        self.context_menu.add_separator()
        export_menu = tk.Menu(self.context_menu, tearoff=0, bg='black', fg='#00ff00')
        self.context_menu.add_cascade(label="Export Packet", menu=export_menu)
        
        # Add export options
        export_menu.add_command(label="as PCAP", command=lambda: self.export_packet("pcap"))
        export_menu.add_command(label="as Text", command=lambda: self.export_packet("txt"))
        export_menu.add_command(label="as JSON", command=lambda: self.export_packet("json"))
        export_menu.add_command(label="as Hex Dump", command=lambda: self.export_packet("hex"))
        export_menu.add_command(label="as Raw Data", command=lambda: self.export_packet("raw"))
        
        # Bind right-click to show menu
        self.packet_tree.bind("<Button-3>", self.show_context_menu)
        
    def update_interface_list(self):
        interfaces = get_working_ifaces()
        self.iface_combo.configure(values=[iface.name for iface in interfaces])
        if self.iface_combo.cget("values"):
            self.iface_combo.set(self.iface_combo.cget("values")[0])
            
    def start_capture(self):
        if not self.is_capturing:
            self.is_capturing = True
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.packet_tree.delete(*self.packet_tree.get_children())
            self.packet_list.clear()
            
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
    def stop_capture(self):
        self.is_capturing = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        
    def capture_packets(self):
        def packet_callback(packet):
            if not self.is_capturing:
                return
            
            # Process packet in the main thread
            self.root.after(0, self.process_packet, packet)
            
        try:
            sniff(iface=self.selected_iface.get(), prn=packet_callback, store=0)
        except Exception as e:
            messagebox.showerror("Error", f"Capture error: {str(e)}")
            self.stop_capture()
            
    def process_packet(self, packet):
        """Process a single packet and return its details"""
        try:
            # Initialize packet info
            packet_info = {
                "time": datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                "length": len(packet),
                "protocol": "Unknown",
                "source": "",
                "destination": "",
                "info": ""
            }

            # Process HTTP content
            if TCP in packet and Raw in packet:
                payload = packet[Raw].load
                if self.process_http_content(packet, payload, packet_info):
                    # Content was processed, update display
                    self.root.after(0, self.update_captured_content_display)
            
            # Layer 2 - Ethernet
            if Ether in packet:
                eth = packet[Ether]
                if eth.type == 0x0806:  # ARP
                    packet_info["protocol"] = "ARP"
                    if ARP in packet:
                        arp = packet[ARP]
                        packet_info["source"] = f"{arp.psrc} ({arp.hwsrc})"
                        packet_info["destination"] = f"{arp.pdst} ({arp.hwdst})"
                        if arp.op == 1:
                            packet_info["info"] = f"Who has {arp.pdst}? Tell {arp.psrc}"
                        else:
                            packet_info["info"] = f"{arp.psrc} is at {arp.hwsrc}"

            # Layer 3 - IP
            if IP in packet:
                ip = packet[IP]
                packet_info["source"] = ip.src
                packet_info["destination"] = ip.dst

                # ICMP
                if ICMP in packet:
                    icmp = packet[ICMP]
                    packet_info["protocol"] = "ICMP"
                    icmp_types = {
                        0: "Echo Reply",
                        3: "Destination Unreachable",
                        5: "Redirect",
                        8: "Echo Request",
                        11: "Time Exceeded"
                    }
                    icmp_type = icmp_types.get(icmp.type, f"Type {icmp.type}")
                    packet_info["info"] = f"{icmp_type}, code {icmp.code}"
                    if Raw in packet:
                        data = packet[Raw].load
                        if len(data) > 0:
                            packet_info["info"] += f" | Data: {data[:20]!r}"

                # TCP
                elif TCP in packet:
                    tcp = packet[TCP]
                    packet_info["source"] += f":{tcp.sport}"
                    packet_info["destination"] += f":{tcp.dport}"
                    
                    # TCP Flags
                    flags = []
                    if tcp.flags.S: flags.append("SYN")
                    if tcp.flags.A: flags.append("ACK")
                    if tcp.flags.F: flags.append("FIN")
                    if tcp.flags.R: flags.append("RST")
                    if tcp.flags.P: flags.append("PSH")
                    if tcp.flags.U: flags.append("URG")
                    
                    # TCP Connection State
                    state = "Unknown"
                    if "SYN" in flags and "ACK" not in flags:
                        state = "Connection Request"
                    elif "SYN" in flags and "ACK" in flags:
                        state = "Connection Established"
                    elif "FIN" in flags:
                        state = "Connection Closing"
                    elif "RST" in flags:
                        state = "Connection Reset"
                    elif "ACK" in flags and len(flags) == 1:
                        state = "Acknowledgment"
                    elif "PSH" in flags and "ACK" in flags:
                        state = "Data Transfer"
                    
                    # TCP Sequence Info
                    seq_info = f"Seq={tcp.seq}"
                    if tcp.flags.A:
                        seq_info += f" Ack={tcp.ack}"
                    
                    # Window Size and Options
                    window_info = f"Win={tcp.window}"
                    if tcp.options:
                        opts = []
                        for opt in tcp.options:
                            if opt[0] == "MSS":
                                opts.append(f"MSS={opt[1]}")
                            elif opt[0] == "WScale":
                                opts.append(f"WS={opt[1]}")
                            elif opt[0] == "Timestamp":
                                opts.append(f"TSval={opt[1][0]} TSecho={opt[1][1]}")
                        if opts:
                            window_info += f" [{' '.join(opts)}]"
                    
                    # Combine all TCP info
                    packet_info["info"] = f"{state}: {' '.join(flags)} {seq_info} {window_info}"
                    
                    # Add data length if present
                    if Raw in packet:
                        data_len = len(packet[Raw].load)
                        packet_info["info"] += f" Len={data_len}"
                    
                    # Special handling for common TCP protocols
                    if tcp.dport == 80 or tcp.sport == 80:  # HTTP
                        packet_info["protocol"] = "HTTP"
                        if Raw in packet:
                            try:
                                http_data = packet[Raw].load.decode('utf-8', errors='ignore')
                                if http_data.startswith(('GET', 'POST', 'HTTP')):
                                    first_line = http_data.split('\r\n')[0]
                                    packet_info["info"] = f"{first_line} ({state})"
                            except:
                                pass
                    elif tcp.dport == 443 or tcp.sport == 443:  # HTTPS
                        packet_info["protocol"] = "HTTPS"
                        packet_info["info"] = f"TLS/SSL {state}"
                    
                    packet_info["protocol"] = "TCP"
                    
                # UDP
                elif UDP in packet:
                    udp = packet[UDP]
                    packet_info["source"] += f":{udp.sport}"
                    packet_info["destination"] += f":{udp.dport}"
                    
                    # DNS
                    if DNS in packet:
                        packet_info["protocol"] = "DNS"
                        dns = packet[DNS]
                        if dns.qr == 0:
                            packet_info["info"] = f"Query: {dns.qd.qname.decode()}"
                        else:
                            answers = []
                            for i in range(dns.ancount):
                                if isinstance(dns.an[i].rdata, bytes):
                                    answers.append(dns.an[i].rdata.decode())
                                else:
                                    answers.append(str(dns.an[i].rdata))
                            packet_info["info"] = f"Response: {', '.join(answers)[:50]}"
                    
                    # DHCP
                    elif udp.sport == 67 or udp.sport == 68:
                        packet_info["protocol"] = "DHCP"
                        if BOOTP in packet:
                            if packet[BOOTP].op == 1:
                                packet_info["info"] = "DHCP Request"
                            else:
                                packet_info["info"] = "DHCP Reply"
                            if Raw in packet:
                                packet_info["info"] += f" ({len(packet[Raw].load)} bytes)"
                    
                    # SNMP
                    elif udp.dport == 161 or udp.sport == 161:
                        packet_info["protocol"] = "SNMP"
                        if Raw in packet:
                            packet_info["info"] = f"SNMP Data ({len(packet[Raw].load)} bytes)"
                    
                    # NTP
                    elif udp.dport == 123 or udp.sport == 123:
                        packet_info["protocol"] = "NTP"
                        if Raw in packet:
                            packet_info["info"] = f"NTP Data ({len(packet[Raw].load)} bytes)"
                    else:
                        packet_info["protocol"] = "UDP"
                        if Raw in packet:
                            data = packet[Raw].load
                            packet_info["info"] = f"Data: {len(data)} bytes"

            # Insert packet into treeview if it matches the filter
            if self.matches_filter(packet_info):
                self.packet_tree.insert("", tk.END, values=(
                    len(self.packet_list) + 1,
                    packet_info["time"],
                    packet_info["source"],
                    packet_info["destination"],
                    packet_info["protocol"],
                    packet_info["length"],
                    packet_info["info"]
                ))
                self.packet_list.append(packet)
                
                # Update statistics
                self.statistics[packet_info["protocol"]] = self.statistics.get(packet_info["protocol"], 0) + 1
            
        except Exception as e:
            print(f"Error processing packet: {e}")

    def get_content_type(self, packet):
        """Detect content type of packet based on headers and signatures"""
        content_type = None
        
        # First check HTTP Content-Type header
        if TCP in packet and Raw in packet:
            raw_data = bytes(packet[Raw])
            try:
                # Try to decode HTTP headers
                headers = raw_data.split(b'\r\n\r\n')[0].decode('utf-8', 'ignore')
                
                # Look for Content-Type header (case-insensitive)
                for line in headers.split('\r\n'):
                    if line.lower().startswith('content-type:'):
                        content_type = line.split(':', 1)[1].strip().lower()
                        # Handle content type with charset
                        content_type = content_type.split(';')[0].strip()
                        break
                
                # Handle special cases
                if content_type:
                    # Handle Office documents
                    if 'officedocument' in content_type:
                        return 'application/msoffice'
                    # Handle SVG images
                    if 'svg' in content_type:
                        return 'image/svg+xml'
                    
            except Exception as e:
                print(f"Error parsing Content-Type: {e}")
        
        # If no Content-Type header or couldn't parse it, try file signatures
        if Raw in packet:
            raw_data = bytes(packet[Raw])
            
            # Skip HTTP headers if present
            header_end = raw_data.find(b'\r\n\r\n')
            if header_end != -1:
                raw_data = raw_data[header_end + 4:]
            
            # Check file signatures
            for sig_type, info in self.content_types.items():
                for sig in info['signature']:
                    if raw_data.startswith(sig):
                        return sig_type
                    # Some signatures might be after some bytes (e.g., WEBP in RIFF)
                    elif len(raw_data) > 12 and sig in raw_data[:12]:
                        return sig_type
        
        return content_type

    def process_http_content(self, packet, payload, packet_info):
        """Process HTTP content from packet payload"""
        try:
            # Check if this is HTTP traffic
            if not (b"HTTP/" in payload or b"GET " in payload or b"POST " in payload):
                return False
            
            # Get content type
            content_type = self.get_content_type(packet)
            if not content_type:
                return False
            
            # Find matching content type
            matched_type = None
            for ct, info in self.content_types.items():
                if content_type.startswith(ct):
                    matched_type = (ct, info)
                    break
            
            if not matched_type:
                return False
            
            ct, info = matched_type
            
            # Extract content
            header_end = payload.find(b'\r\n\r\n')
            if header_end == -1:
                return False
            
            content = payload[header_end + 4:]
            
            # Verify content using signatures
            is_valid = False
            if info['signature']:
                for sig in info['signature']:
                    if sig in content[:20]:
                        is_valid = True
                        break
            else:
                is_valid = True
            
            if not is_valid:
                return False
            
            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"captured_{timestamp}{info['ext']}"
            
            # Create save directory
            save_path = os.path.join("captured_content", info['category'])
            os.makedirs(save_path, exist_ok=True)
            
            # Ensure unique filename
            base, ext = os.path.splitext(filename)
            counter = 1
            file_path = os.path.join(save_path, filename)
            while os.path.exists(file_path):
                filename = f"{base}_{counter}{ext}"
                file_path = os.path.join(save_path, filename)
                counter += 1
            
            # Save content
            with open(file_path, 'wb') as f:
                f.write(content)
            
            # Store file info
            file_info = {
                'filename': filename,
                'path': file_path,
                'type': content_type,
                'size': len(content),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.captured_files[info['category']].append(file_info)
            
            return True
            
        except Exception as e:
            print(f"Error processing HTTP content: {e}")
            return False

    def format_hex_dump(self, data):
        """Create a formatted hex dump with both hex and ASCII representation"""
        def grouper(iterable, n):
            args = [iter(iterable)] * n
            return zip_longest(*args, fillvalue=' ')

        def to_ascii(byte):
            if isinstance(byte, int) and 32 <= byte <= 126:
                return chr(byte)
            elif isinstance(byte, str) and byte != ' ':
                byte_val = ord(byte)
                if 32 <= byte_val <= 126:
                    return byte
            return '.'

        result = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            
            # Hex part
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            hex_formatted = ' '.join(hex_part[j:j+24] for j in range(0, len(hex_part), 24))
            
            # ASCII part
            ascii_part = ''.join(to_ascii(b) for b in chunk)
            
            # Combine parts
            line = f'{i:04x}  {hex_formatted:<48}  |{ascii_part:<16}|'
            result.append(line)
        
        return '\n'.join(result)

    def show_packet_details(self, packet):
        """Show detailed packet information in tree view"""
        # Clear previous details
        for item in self.details_tree.get_children():
            self.details_tree.delete(item)
            
        # Show hex dump with both hex and ASCII
        if Raw in packet:
            raw_data = packet[Raw].load
            hex_dump = self.format_hex_dump(raw_data)
            self.hex_view.delete('1.0', tk.END)
            self.hex_view.insert('1.0', f"Hex Dump:\n{hex_dump}")
            
            # Try to show as text if printable
            try:
                text_data = raw_data.decode('utf-8', errors='ignore')
                if any(32 <= ord(c) <= 126 for c in text_data):
                    self.hex_view.insert(tk.END, f"\n\nASCII Data:\n{text_data}")
            except:
                pass
        else:
            self.hex_view.delete('1.0', tk.END)
            self.hex_view.insert('1.0', "No raw data available")

    def on_packet_select(self, event):
        """Show detailed packet information in tree view"""
        selection = self.packet_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        packet = self.packet_list[int(self.packet_tree.item(item)["values"][0]) - 1]
        
        # Clear previous details
        for item in self.details_tree.get_children():
            self.details_tree.delete(item)
        
        # Frame details
        frame_item = self.details_tree.insert("", tk.END, text=" Frame", open=True)
        self.details_tree.insert(frame_item, tk.END, 
                               text=f"Arrival Time: {datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
        self.details_tree.insert(frame_item, tk.END, 
                               text=f"Frame Length: {len(packet)} bytes")
        
        # Ethernet Layer
        if Ether in packet:
            eth_item = self.details_tree.insert("", tk.END, text=" Ethernet", open=True)
            eth = packet[Ether]
            self.details_tree.insert(eth_item, tk.END, text=f"Source MAC: {eth.src}")
            self.details_tree.insert(eth_item, tk.END, text=f"Destination MAC: {eth.dst}")
            self.details_tree.insert(eth_item, tk.END, text=f"Type: 0x{eth.type:04x}")

        # ARP
        if ARP in packet:
            arp_item = self.details_tree.insert("", tk.END, text=" Address Resolution Protocol", open=True)
            arp = packet[ARP]
            self.details_tree.insert(arp_item, tk.END, text=f"Operation: {'Request' if arp.op == 1 else 'Reply'}")
            self.details_tree.insert(arp_item, tk.END, text=f"Sender MAC: {arp.hwsrc}")
            self.details_tree.insert(arp_item, tk.END, text=f"Sender IP: {arp.psrc}")
            self.details_tree.insert(arp_item, tk.END, text=f"Target MAC: {arp.hwdst}")
            self.details_tree.insert(arp_item, tk.END, text=f"Target IP: {arp.pdst}")
        
        # IP Layer
        if IP in packet:
            ip_item = self.details_tree.insert("", tk.END, text=" Internet Protocol", open=True)
            ip = packet[IP]
            self.details_tree.insert(ip_item, tk.END, text=f"Version: {ip.version}")
            self.details_tree.insert(ip_item, tk.END, text=f"Header Length: {ip.ihl * 4} bytes")
            self.details_tree.insert(ip_item, tk.END, text=f"Total Length: {ip.len} bytes")
            self.details_tree.insert(ip_item, tk.END, text=f"TTL: {ip.ttl}")
            self.details_tree.insert(ip_item, tk.END, text=f"Protocol: {ip.proto}")
            self.details_tree.insert(ip_item, tk.END, text=f"Source IP: {ip.src}")
            self.details_tree.insert(ip_item, tk.END, text=f"Destination IP: {ip.dst}")
        
        # ICMP
        if ICMP in packet:
            icmp_item = self.details_tree.insert("", tk.END, text=" ICMP", open=True)
            icmp = packet[ICMP]
            icmp_types = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                5: "Redirect",
                8: "Echo Request",
                11: "Time Exceeded"
            }
            icmp_type = icmp_types.get(icmp.type, f"Type {icmp.type}")
            self.details_tree.insert(icmp_item, tk.END, text=f"Type: {icmp_type}")
            self.details_tree.insert(icmp_item, tk.END, text=f"Code: {icmp.code}")
            if hasattr(icmp, 'id'):
                self.details_tree.insert(icmp_item, tk.END, text=f"Identifier: {icmp.id}")
            if hasattr(icmp, 'seq'):
                self.details_tree.insert(icmp_item, tk.END, text=f"Sequence: {icmp.seq}")

        # TCP Layer
        if TCP in packet:
            tcp_item = self.details_tree.insert("", tk.END, text=" Transmission Control Protocol", open=True)
            tcp = packet[TCP]
            self.details_tree.insert(tcp_item, tk.END, text=f"Source Port: {tcp.sport}")
            self.details_tree.insert(tcp_item, tk.END, text=f"Destination Port: {tcp.dport}")
            self.details_tree.insert(tcp_item, tk.END, text=f"Sequence Number: {tcp.seq}")
            self.details_tree.insert(tcp_item, tk.END, text=f"Acknowledgment: {tcp.ack}")
            self.details_tree.insert(tcp_item, tk.END, text=f"Window Size: {tcp.window}")
            
            # TCP Flags
            flags_item = self.details_tree.insert(tcp_item, tk.END, text="Flags", open=True)
            flags = {
                'SYN': tcp.flags.S,
                'ACK': tcp.flags.A,
                'FIN': tcp.flags.F,
                'RST': tcp.flags.R,
                'PSH': tcp.flags.P,
                'URG': tcp.flags.U
            }
            for flag, value in flags.items():
                if value:
                    self.details_tree.insert(flags_item, tk.END, text=f" {flag}")

        # UDP Layer
        if UDP in packet:
            udp_item = self.details_tree.insert("", tk.END, text=" User Datagram Protocol", open=True)
            udp = packet[UDP]
            self.details_tree.insert(udp_item, tk.END, text=f"Source Port: {udp.sport}")
            self.details_tree.insert(udp_item, tk.END, text=f"Destination Port: {udp.dport}")
            self.details_tree.insert(udp_item, tk.END, text=f"Length: {udp.len}")

        # DNS Layer
        if DNS in packet:
            dns_item = self.details_tree.insert("", tk.END, text=" Domain Name System", open=True)
            dns = packet[DNS]
            self.details_tree.insert(dns_item, tk.END, text=f"Transaction ID: 0x{dns.id:04x}")
            
            # Query or Response
            if dns.qr == 0:
                self.details_tree.insert(dns_item, tk.END, text="Type: Query")
            else:
                self.details_tree.insert(dns_item, tk.END, text="Type: Response")
            
            # Queries
            if dns.qd:
                queries_item = self.details_tree.insert(dns_item, tk.END, text="Queries", open=True)
                self.details_tree.insert(queries_item, tk.END, 
                                      text=f"Name: {dns.qd.qname.decode()}")
                self.details_tree.insert(queries_item, tk.END, 
                                      text=f"Type: {dns.qd.qtype}")
            
            # Answers
            if dns.an:
                answers_item = self.details_tree.insert(dns_item, tk.END, text="Answers", open=True)
                for i in range(dns.ancount):
                    if isinstance(dns.an[i].rdata, bytes):
                        rdata = dns.an[i].rdata.decode()
                    else:
                        rdata = str(dns.an[i].rdata)
                    self.details_tree.insert(answers_item, tk.END,
                                          text=f"Answer {i+1}: {rdata}")

        # HTTP Layer
        if TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
            if Raw in packet:
                try:
                    http_data = packet[Raw].load.decode('utf-8', errors='ignore')
                    if http_data.startswith(('GET', 'POST', 'HTTP')):
                        http_item = self.details_tree.insert("", tk.END, text=" Hypertext Transfer Protocol", open=True)
                        lines = http_data.split('\r\n')
                        for line in lines:
                            if line:
                                self.details_tree.insert(http_item, tk.END, text=line)
                except:
                    pass

        # Raw Data
        if Raw in packet:
            raw_item = self.details_tree.insert("", tk.END, text=" Application Data", open=True)
            raw_data = packet[Raw].load
            try:
                # Try to decode as text
                text_data = raw_data.decode('utf-8', errors='ignore')
                if text_data.isprintable():
                    self.details_tree.insert(raw_item, tk.END, text=f"Text: {text_data}")
            except:
                pass
            
            # Show hex dump
            hex_dump = self.format_hex_dump(raw_data)
            self.hex_view.delete('1.0', tk.END)
            self.hex_view.insert('1.0', f"Hex Dump:\n{hex_dump}")
        
    def show_context_menu(self, event):
        """Show context menu at mouse position"""
        try:
            # Get item under cursor
            item = self.packet_tree.identify_row(event.y)
            if item:
                # Select the item
                self.packet_tree.selection_set(item)
                # Show menu
                self.context_menu.post(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def show_hex_view(self):
        """Show packet data in hex view"""
        try:
            selected = self.packet_tree.selection()[0]
            packet_index = int(self.packet_tree.item(selected)["values"][0]) - 1
            packet = self.packet_list[packet_index]
            
            if Raw in packet:
                data = bytes(packet[Raw])
                hex_window = tk.Toplevel(self.root)
                hex_window.title("Hex View")
                hex_window.geometry("800x600")
                
                # Create text widget with scrollbar
                text = tk.Text(hex_window, wrap=tk.NONE, font=("Courier", 10), bg='black', fg='#00ff00')
                scrolly = ttk.Scrollbar(hex_window, orient="vertical", command=text.yview)
                scrollx = ttk.Scrollbar(hex_window, orient="horizontal", command=text.xview)
                text.configure(yscrollcommand=scrolly.set, xscrollcommand=scrollx.set)
                
                # Pack widgets
                text.grid(row=0, column=0, sticky="nsew")
                scrolly.grid(row=0, column=1, sticky="ns")
                scrollx.grid(row=1, column=0, sticky="ew")
                
                # Configure grid
                hex_window.grid_rowconfigure(0, weight=1)
                hex_window.grid_columnconfigure(0, weight=1)
                
                # Insert hex dump
                text.insert(tk.END, self.format_hex_dump(data))
                text.configure(state="disabled")
            else:
                messagebox.showinfo("Info", "No raw data in packet!")
                
        except IndexError:
            messagebox.showerror("Error", "No packet selected!")

    def show_full_headers(self):
        """Show full packet headers in a new window"""
        try:
            selected = self.packet_tree.selection()[0]
            packet_index = int(self.packet_tree.item(selected)["values"][0]) - 1
            packet = self.packet_list[packet_index]
            
            # Create new window
            header_window = tk.Toplevel(self.root)
            header_window.title("Full Packet Headers")
            header_window.geometry("800x600")
            
            # Create text widget with scrollbar
            text = tk.Text(header_window, wrap=tk.NONE, bg='black', fg='#00ff00')
            scrolly = ttk.Scrollbar(header_window, orient="vertical", command=text.yview)
            scrollx = ttk.Scrollbar(header_window, orient="horizontal", command=text.xview)
            text.configure(yscrollcommand=scrolly.set, xscrollcommand=scrollx.set)
            
            # Pack widgets
            text.grid(row=0, column=0, sticky="nsew")
            scrolly.grid(row=0, column=1, sticky="ns")
            scrollx.grid(row=1, column=0, sticky="ew")
            
            # Configure grid
            header_window.grid_rowconfigure(0, weight=1)
            header_window.grid_columnconfigure(0, weight=1)
            
            # Insert packet headers
            text.insert(tk.END, packet.show(dump=True))
            text.configure(state="disabled")
            
        except IndexError:
            messagebox.showerror("Error", "No packet selected!")

    def show_content(self, content_type):
        """Show packet content based on type"""
        try:
            selected = self.packet_tree.selection()[0]
            packet_index = int(self.packet_tree.item(selected)["values"][0]) - 1
            packet = self.packet_list[packet_index]
            
            if not Raw in packet:
                messagebox.showinfo("Info", "No content data in packet!")
                return
                
            data = bytes(packet[Raw])
            
            if content_type == "text":
                self.show_text_content(data)
            elif content_type == "image":
                self.show_image_content(data)
            elif content_type == "audio":
                self.show_audio_content(data)
            elif content_type == "document":
                self.show_document_content(data)
            elif content_type == "hex":
                self.show_hex_view()
                
        except IndexError:
            messagebox.showerror("Error", "No packet selected!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show content: {str(e)}")

    def show_text_content(self, data):
        """Show content as text"""
        try:
            # Try different encodings
            encodings = ['utf-8', 'ascii', 'iso-8859-1']
            text_content = None
            
            for encoding in encodings:
                try:
                    text_content = data.decode(encoding)
                    break
                except:
                    continue
            
            if text_content is None:
                messagebox.showerror("Error", "Could not decode text content!")
                return
            
            # Create window
            text_window = tk.Toplevel(self.root)
            text_window.title("Text Content")
            text_window.geometry("800x600")
            
            # Create text widget with scrollbar
            text = tk.Text(text_window, wrap=tk.WORD, bg='black', fg='#00ff00')
            scrolly = ttk.Scrollbar(text_window, orient="vertical", command=text.yview)
            text.configure(yscrollcommand=scrolly.set)
            
            # Pack widgets
            text.pack(side="left", fill="both", expand=True)
            scrolly.pack(side="right", fill="y")
            
            # Insert text
            text.insert(tk.END, text_content)
            text.configure(state="disabled")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show text content: {str(e)}")

    def show_image_content(self, data):
        """Show content as image"""
        try:
            # Create temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            
            # Try to open image
            try:
                image = Image.open(tmp_path)
                
                # Create window
                image_window = tk.Toplevel(self.root)
                image_window.title("Image Content")
                
                # Convert to PhotoImage
                photo = ImageTk.PhotoImage(image)
                
                # Create label
                label = tk.Label(image_window, image=photo)
                label.image = photo  # Keep a reference
                label.pack()
                
                # Set window size based on image
                width = min(image.width, 800)
                height = min(image.height, 600)
                image_window.geometry(f"{width}x{height}")
                
            finally:
                # Clean up temp file
                os.unlink(tmp_path)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show image content: {str(e)}")

    def show_document_content(self, data):
        """Show document content info"""
        try:
            # Try to identify document type
            if data.startswith(b'%PDF'):
                doc_type = "PDF"
            elif data.startswith(b'\xD0\xCF\x11\xE0'):
                doc_type = "Microsoft Office"
            else:
                doc_type = "Unknown"
            
            # Save temporary file
            ext = '.pdf' if doc_type == "PDF" else '.doc'
            with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            
            # Ask user if they want to open the file
            if messagebox.askyesno("Document Content",
                                 f"Detected {doc_type} document. Open with default application?"):
                os.startfile(tmp_path)
            else:
                os.unlink(tmp_path)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to handle document content: {str(e)}")

    def show_audio_content(self, data):
        """Show audio content info"""
        try:
            # Try to identify audio type
            if data.startswith(b'ID3') or data.startswith(b'\xFF\xFB'):
                audio_type = "MP3"
            elif data.startswith(b'RIFF'):
                audio_type = "WAV"
            else:
                audio_type = "Unknown"
            
            # Save temporary file
            ext = '.mp3' if audio_type == "MP3" else '.wav'
            with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            
            # Ask user if they want to open the file
            if messagebox.askyesno("Audio Content",
                                 f"Detected {audio_type} audio. Open with default application?"):
                os.startfile(tmp_path)
            else:
                os.unlink(tmp_path)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to handle audio content: {str(e)}")
    
    def apply_filter(self):
        filter_text = self.filter_text.get().lower()
        for item in self.packet_tree.get_children():
            values = self.packet_tree.item(item)["values"]
            show = any(filter_text in str(value).lower() for value in values)
            if show:
                self.packet_tree.reattach(item, "", tk.END)
            else:
                self.packet_tree.detach(item)
                
    def matches_filter(self, packet_info):
        """Check if packet matches current filter settings"""
        # TCP Flags filter
        if self.tcp_flags_var.get() != "ALL":
            flag = self.tcp_flags_var.get()
            if flag not in packet_info["info"]:
                return False
        
        return True

    def show_tcp_details(self, packet):
        """Show detailed TCP information in the details tree"""
        if TCP in packet and IP in packet:
            tcp = packet[TCP]
            ip = packet[IP]
            
            # TCP Header
            tcp_item = self.details_tree.insert("", tk.END, text="🔗 TCP Header", open=True)
            
            # Basic Info
            basic = self.details_tree.insert(tcp_item, tk.END, text="Basic Information", open=True)
            self.details_tree.insert(basic, tk.END, text=f"Source Port: {tcp.sport}")
            self.details_tree.insert(basic, tk.END, text=f"Destination Port: {tcp.dport}")
            self.details_tree.insert(basic, tk.END, text=f"Header Length: {tcp.dataofs * 4} bytes")
            
            # Sequence Numbers
            seq = self.details_tree.insert(tcp_item, tk.END, text="Sequence Numbers", open=True)
            self.details_tree.insert(seq, tk.END, text=f"Sequence Number: {tcp.seq}")
            self.details_tree.insert(seq, tk.END, text=f"Next Sequence Number: {tcp.seq + len(packet[Raw].load) if Raw in packet else tcp.seq}")
            if tcp.flags.A:
                self.details_tree.insert(seq, tk.END, text=f"Acknowledgment Number: {tcp.ack}")
            
            # Flags
            flags = self.details_tree.insert(tcp_item, tk.END, text="Flags", open=True)
            flag_bits = {
                'URG': tcp.flags.U, 'ACK': tcp.flags.A,
                'PSH': tcp.flags.P, 'RST': tcp.flags.R,
                'SYN': tcp.flags.S, 'FIN': tcp.flags.F
            }
            for name, value in flag_bits.items():
                self.details_tree.insert(flags, tk.END, text=f"{name}: {'✓' if value else '✗'}")
            
            # Window
            window = self.details_tree.insert(tcp_item, tk.END, text="Window", open=True)
            self.details_tree.insert(window, tk.END, text=f"Window Size: {tcp.window}")
            self.details_tree.insert(window, tk.END, text=f"Calculated Window: {tcp.window * (2 ** next((opt[1] for opt in tcp.options if opt[0] == 'WScale'), 0))}")
            
            # Options
            if tcp.options:
                options = self.details_tree.insert(tcp_item, tk.END, text="Options", open=True)
                for opt in tcp.options:
                    if opt[0] == "MSS":
                        self.details_tree.insert(options, tk.END, text=f"Maximum Segment Size: {opt[1]} bytes")
                    elif opt[0] == "WScale":
                        self.details_tree.insert(options, tk.END, text=f"Window Scale: {opt[1]} (multiply by {2 ** opt[1]})")
                    elif opt[0] == "Timestamp":
                        self.details_tree.insert(options, tk.END, text=f"Timestamp Value: {opt[1][0]}")
                        self.details_tree.insert(options, tk.END, text=f"Timestamp Echo Reply: {opt[1][1]}")
                    elif opt[0] == "SAckOK":
                        self.details_tree.insert(options, tk.END, text="Selective Acknowledgment Permitted")
            
            # Checksum
            checksum = self.details_tree.insert(tcp_item, tk.END, text="Checksum", open=True)
            self.details_tree.insert(checksum, tk.END, text=f"Checksum: 0x{tcp.chksum:04x}")
            
            # Payload
            if Raw in packet:
                payload = self.details_tree.insert(tcp_item, tk.END, text="Payload", open=True)
                self.details_tree.insert(payload, tk.END, text=f"Length: {len(packet[Raw].load)} bytes")
                
    def show_statistics(self):
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Capture Statistics")
        stats_window.geometry("400x300")
        
        text_widget = tk.Text(stats_window, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        stats_text = "Capture Statistics:\n\n"
        for key, value in self.statistics.items():
            stats_text += f"{key}: {value}\n"
            
        text_widget.insert(tk.END, stats_text)
        text_widget.configure(state=tk.DISABLED)

    def save_capture(self):
        if not self.packet_list:
            messagebox.showwarning("Warning", "No packets to save!")
            return
            
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"capture_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write("=== Network Capture Log ===\n\n")
                f.write(f"Capture Time: {datetime.now()}\n")
                f.write(f"Total Packets: {len(self.packet_list)}\n\n")
                
                for i, packet in enumerate(self.packet_list, 1):
                    f.write(f"Packet #{i}\n")
                    f.write(f"{'='*50}\n")
                    f.write(packet.show(dump=True))
                    f.write("\n\n")
            
            self.status_var.set(f"Capture saved to {filename}")
            messagebox.showinfo("Success", f"Capture saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save capture: {str(e)}")
    
    def clear_capture(self):
        if messagebox.askyesno("Clear Capture", "Are you sure you want to clear all captured packets?"):
            self.packet_list.clear()
            self.packet_tree.delete(*self.packet_tree.get_children())
            self.details_tree.delete(*self.details_tree.get_children())
            self.hex_view.delete(1.0, tk.END)
            self.statistics.clear()
            self.status_var.set("Capture cleared")
            
    def show_captured_content(self):
        """Show window with captured content"""
        # Close existing window if open
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Toplevel) and widget.wm_title() == "Captured Web Content":
                widget.destroy()
        
        # Create new window
        content_window = tk.Toplevel(self.root)
        content_window.title("Captured Web Content")
        content_window.geometry("1000x600")
        
        # Create notebook for different content types
        style = ttk.Style()
        style.configure("Custom.TNotebook", background="#2b2b2b")
        style.configure("Custom.TNotebook.Tab", background="#2b2b2b", foreground="white")
        
        notebook = ttk.Notebook(content_window, style="Custom.TNotebook")
        notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create tabs for each content type
        for category in self.captured_files.keys():
            frame = ttk.Frame(notebook)
            notebook.add(frame, text=category.title())
            
            # Create treeview
            tree = ttk.Treeview(frame, columns=("Filename", "Type", "Size", "Time"), show="headings")
            tree.heading("Filename", text="Filename")
            tree.heading("Type", text="Content Type")
            tree.heading("Size", text="Size")
            tree.heading("Time", text="Timestamp")
            
            # Configure column widths
            tree.column("Filename", width=200)
            tree.column("Type", width=150)
            tree.column("Size", width=100)
            tree.column("Time", width=150)
            
            # Add scrollbar
            scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=scrollbar.set)
            
            # Pack widgets
            tree.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Populate tree
            for file_info in self.captured_files[category]:
                size_str = f"{file_info['size'] / 1024:.1f} KB"
                tree.insert("", "end", values=(
                    file_info['filename'],
                    file_info['type'],
                    size_str,
                    file_info['timestamp']
                ))
            
            # Add right-click menu
            menu = tk.Menu(tree, tearoff=0)
            menu.add_command(label="Open File", 
                           command=lambda t=tree, c=category: self.open_captured_file(t, c))
            menu.add_command(label="Open Containing Folder",
                           command=lambda t=tree, c=category: self.open_containing_folder(t, c))
            menu.add_separator()
            menu.add_command(label="Delete File",
                           command=lambda t=tree, c=category: self.delete_captured_file(t, c))
            
            tree.bind("<Button-3>", lambda e, m=menu: self.show_file_menu(e, m))
            tree.bind("<Double-1>", lambda e, t=tree, c=category: self.open_captured_file(t, c))
    
    def show_file_menu(self, event, menu):
        """Show right-click menu for file"""
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
    
    def open_captured_file(self, tree, category):
        """Open captured file with default system application"""
        try:
            item = tree.selection()[0]
            filename = tree.item(item)["values"][0]
            
            # Find file info
            file_info = next((f for f in self.captured_files[category] if f['filename'] == filename), None)
            if file_info and os.path.exists(file_info['path']):
                os.startfile(file_info['path'])
            else:
                messagebox.showerror("Error", "File not found!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file: {str(e)}")
    
    def open_containing_folder(self, tree, category):
        """Open folder containing the file"""
        try:
            item = tree.selection()[0]
            filename = tree.item(item)["values"][0]
            
            # Find file info
            file_info = next((f for f in self.captured_files[category] if f['filename'] == filename), None)
            if file_info and os.path.exists(file_info['path']):
                os.startfile(os.path.dirname(file_info['path']))
            else:
                messagebox.showerror("Error", "Folder not found!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open folder: {str(e)}")
    
    def delete_captured_file(self, tree, category):
        """Delete captured file"""
        try:
            item = tree.selection()[0]
            filename = tree.item(item)["values"][0]
            
            # Find file info
            file_info = next((f for f in self.captured_files[category] if f['filename'] == filename), None)
            if file_info and os.path.exists(file_info['path']):
                if messagebox.askyesno("Confirm Delete", f"Delete {filename}?"):
                    os.remove(file_info['path'])
                    self.captured_files[category].remove(file_info)
                    tree.delete(item)
            else:
                messagebox.showerror("Error", "File not found!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete file: {str(e)}")
    
    def update_captured_content_display(self):
        """Update the captured content display if window is open"""
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Toplevel) and widget.wm_title() == "Captured Web Content":
                self.show_captured_content()
                break

    def save_pcap(self):
        """Save captured packets to PCAP file"""
        if not self.packet_list:
            messagebox.showwarning("Warning", "No packets to save!")
            return
            
        try:
            # Get save location
            filename = filedialog.asksaveasfilename(
                title="Save Captured Packets",
                defaultextension=".pcap",
                filetypes=[
                    ("PCAP files", "*.pcap"),
                    ("All files", "*.*")
                ]
            )
            
            if not filename:
                return
                
            # Save packets
            wrpcap(filename, self.packet_list)
            messagebox.showinfo("Success", f"Successfully saved {len(self.packet_list)} packets to {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PCAP file: {str(e)}")

    def export_selected_packet(self, format_type):
        """Export selected packet in specified format"""
        try:
            selected = self.packet_tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Please select a packet to export!")
                return
                
            packet_index = int(self.packet_tree.item(selected[0])["values"][0]) - 1
            packet = self.packet_list[packet_index]
            
            # Get current timestamp for filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Configure export based on format
            if format_type == "pcap":
                default_name = f"packet_{timestamp}.pcap"
                file_types = [("PCAP files", "*.pcap")]
                
            elif format_type == "txt":
                default_name = f"packet_{timestamp}.txt"
                file_types = [("Text files", "*.txt")]
                
            elif format_type == "json":
                default_name = f"packet_{timestamp}.json"
                file_types = [("JSON files", "*.json")]
                
            elif format_type == "hex":
                default_name = f"packet_{timestamp}_hex.txt"
                file_types = [("Text files", "*.txt")]
                
            elif format_type == "raw":
                default_name = f"packet_{timestamp}_raw"
                file_types = [("All files", "*.*")]
            
            # Add all files option
            file_types.append(("All files", "*.*"))
            
            # Get save location
            filename = filedialog.asksaveasfilename(
                title=f"Export Packet as {format_type.upper()}",
                defaultextension=f".{format_type}",
                initialfile=default_name,
                filetypes=file_types
            )
            
            if not filename:
                return
                
            # Export based on format
            if format_type == "pcap":
                wrpcap(filename, [packet])
                
            elif format_type == "txt":
                with open(filename, 'w') as f:
                    # Write packet summary
                    f.write("=== Packet Summary ===\n")
                    f.write(f"Time: {datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')}\n")
                    f.write(f"Length: {len(packet)} bytes\n\n")
                    
                    # Write detailed packet info
                    f.write("=== Packet Details ===\n")
                    f.write(packet.show(dump=True))
                    
            elif format_type == "json":
                packet_dict = {
                    "time": datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f'),
                    "length": len(packet),
                    "layers": {}
                }
                
                # Add layer information
                for layer in packet.layers():
                    layer_name = layer.__name__
                    packet_dict["layers"][layer_name] = {}
                    
                    # Add all fields from the layer
                    for field in layer.fields_desc:
                        if hasattr(packet[layer_name], field.name):
                            value = getattr(packet[layer_name], field.name)
                            # Convert bytes to hex string if needed
                            if isinstance(value, bytes):
                                value = value.hex()
                            packet_dict["layers"][layer_name][field.name] = str(value)
                
                with open(filename, 'w') as f:
                    json.dump(packet_dict, f, indent=2)
                    
            elif format_type == "hex":
                with open(filename, 'w') as f:
                    # Write hex dump with offset and ASCII
                    hex_dump = hexdump(bytes(packet), result='return')
                    f.write(hex_dump)
                    
            elif format_type == "raw":
                with open(filename, 'wb') as f:
                    f.write(bytes(packet))
            
            messagebox.showinfo("Success", f"Packet exported successfully as {format_type.upper()}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export packet: {str(e)}")

    def export_packet(self, format_type):
        """Export packet with error handling"""
        try:
            self.export_selected_packet(format_type)
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
            
    def create_context_menu(self):
        """Create right-click context menu for packet list"""
        # Create main context menu
        self.context_menu = tk.Menu(self.root, tearoff=0, bg='black', fg='#00ff00')
        
        # Add menu items
        self.context_menu.add_command(label="Show Full Headers", command=self.show_full_headers)
        self.context_menu.add_command(label="Show Hex View", command=self.show_hex_view)
        self.context_menu.add_separator()
        
        # Content analysis submenu
        self.content_menu = tk.Menu(self.context_menu, tearoff=0, bg='black', fg='#00ff00')
        self.context_menu.add_cascade(label="Content Analysis", menu=self.content_menu)
        
        # Add content analysis options
        self.content_menu.add_command(label="Show as Text", command=lambda: self.show_content("text"))
        self.content_menu.add_command(label="Show as Image", command=lambda: self.show_content("image"))
        self.content_menu.add_command(label="Show as Audio", command=lambda: self.show_content("audio"))
        self.content_menu.add_command(label="Show as Document", command=lambda: self.show_content("document"))
        self.content_menu.add_command(label="Show as Hex", command=lambda: self.show_content("hex"))
        
        # Export submenu
        self.context_menu.add_separator()
        export_menu = tk.Menu(self.context_menu, tearoff=0, bg='black', fg='#00ff00')
        self.context_menu.add_cascade(label="Export Packet", menu=export_menu)
        
        # Add export options
        export_menu.add_command(label="as PCAP", command=lambda: self.export_packet("pcap"))
        export_menu.add_command(label="as Text", command=lambda: self.export_packet("txt"))
        export_menu.add_command(label="as JSON", command=lambda: self.export_packet("json"))
        export_menu.add_command(label="as Hex Dump", command=lambda: self.export_packet("hex"))
        export_menu.add_command(label="as Raw Data", command=lambda: self.export_packet("raw"))
        
        # Bind right-click to show menu
        self.packet_tree.bind("<Button-3>", self.show_context_menu)
        
def main():
    root = PacketCaptureGUI()
    root.root.mainloop()

if __name__ == "__main__":
    main()
