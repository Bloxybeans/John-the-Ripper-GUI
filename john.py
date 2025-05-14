import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import subprocess
import threading
import os
import shlex
import re

class ToolTip:
    """
    Create a tooltip for a given widget.
    """
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        widget.bind("<Enter>", self.show_tooltip)
        widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        if self.tooltip_window or not event: # If already shown or no event, do nothing
            return

        # Use event.x_root and event.y_root for screen coordinates of the mouse
        # This is more robust than widget.bbox("insert") for non-text widgets
        x = event.x_root + 20  # Offset from cursor X
        y = event.y_root + 15  # Offset from cursor Y

        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True) # Frameless window
        self.tooltip_window.wm_geometry(f"+{x}+{y}")

        label = ttk.Label(self.tooltip_window, text=self.text, justify=tk.LEFT,
                          background="#FFFFE0", relief="solid", borderwidth=1, 
                          padding=(5,3), font=("TkDefaultFont", 9)) # Standard font, slightly smaller
        label.pack(ipadx=1)

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
        self.tooltip_window = None


class JTR_GUI_Enhanced:
    # Common filenames that often contain hashes (case-insensitive)
    KNOWN_HASH_FILENAMES = {
        "shadow", "passwd", "master.passwd", "config.sam", 
        "user.hashes", "ntds.dit", "secrets.txt", "credentials.txt",
        "dump.txt", "hashes.txt", "passwords.txt", "pwdump.txt",
        "john.pot" # JtR's own cracked password file
    }
    # Common extensions for files that might contain hashes (case-insensitive)
    KNOWN_HASH_EXTENSIONS = {
        ".txt", ".lst", ".hash", ".shadow", ".pwd", ".pot", ".ntds", ".sam"
    }
    # Keywords to look for in filenames (case-insensitive)
    KEYWORDS_IN_FILENAME = {
        "hash", "password", "credential", "dump", "leak", "secret", "pwd", "shadow", "backup"
    }
    # Basic regex patterns for common hash types (can be expanded)
    HASH_PATTERNS_SAMPLE = {
        "md5_hex": re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),
        "sha1_hex": re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE),
        "sha256_hex": re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE),
        "ntlm": re.compile(r"^[a-f0-9]{32}:[a-f0-9]{32}$", re.IGNORECASE), 
        "lm": re.compile(r"^[a-f0-9]{16}:[a-f0-9]{16}$", re.IGNORECASE), 
        "wordpress_md5": re.compile(r"^\$P\$[a-zA-Z0-9./]{31}$"),
        "django_sha256": re.compile(r"^pbkdf2_sha256\$[0-9]+\$[a-zA-Z0-9./=+]+\$[a-zA-Z0-9./=+-]+$"),
        "unix_crypt": re.compile(r"^[a-zA-Z0-9./]{13}$"), 
        "sha512crypt": re.compile(r"^\$6\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$"),
        "phpass": re.compile(r"^\$[PH]\$[a-zA-Z0-9./]{31}$"),
    }
    MAX_CONTENT_CHECK_LINES = 20 # Max lines to check for content regex matching


    def __init__(self, master):
        self.master = master
        master.title("John the Ripper GUI")
        master.geometry("850x800") 

        self.style = ttk.Style()
        self.style.theme_use('clam') 

        # --- Main PanedWindow for resizable sections ---
        main_paned_window = ttk.PanedWindow(master, orient=tk.VERTICAL)
        main_paned_window.pack(fill=tk.BOTH, expand=True)

        # --- Top Frame for Configuration and Controls ---
        top_frame = ttk.Frame(main_paned_window)
        main_paned_window.add(top_frame, weight=0) # Do not expand this part much vertically

        # --- Notebook for Tabs ---
        self.notebook = ttk.Notebook(top_frame)
        self.notebook.pack(padx=10, pady=10, fill="x", expand=True)

        # --- Tab 1: Main Settings ---
        self.tab_main = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_main, text='Main Settings')
        self.create_main_settings_tab()

        # --- Tab 2: Advanced Cracking Options ---
        self.tab_advanced = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_advanced, text='Advanced Options')
        self.create_advanced_options_tab()

        # --- Tab 3: Hash File Scanner ---
        self.tab_scanner = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_scanner, text='Hash File Scanner')
        self.create_scanner_tab()


        # --- Control Frame (Start, Stop, Show Cracked) ---
        control_frame = ttk.LabelFrame(top_frame, text="Controls", padding=(10, 5))
        control_frame.pack(padx=10, pady=(0,10), fill="x")

        self.run_button = ttk.Button(control_frame, text="Start John the Ripper", command=self.start_jtr_thread, style="Accent.TButton")
        self.run_button.pack(side="left", padx=5, pady=5)
        ToolTip(self.run_button, "Begin the password cracking process with current settings.")

        self.show_cracked_button = ttk.Button(control_frame, text="Show Cracked Passwords", command=self.show_cracked_passwords_thread)
        self.show_cracked_button.pack(side="left", padx=5, pady=5)
        ToolTip(self.show_cracked_button, "Display passwords already cracked for the specified hash file.")
        
        self.stop_button = ttk.Button(control_frame, text="Stop John", command=self.stop_jtr_process, state=tk.DISABLED)
        self.stop_button.pack(side="left", padx=5, pady=5)
        ToolTip(self.stop_button, "Attempt to terminate the currently running John the Ripper process.")

        # --- Utilities Frame ---
        utilities_frame = ttk.LabelFrame(top_frame, text="Utilities", padding=(10,5))
        utilities_frame.pack(padx=10, pady=(0,10), fill="x")

        self.list_formats_button = ttk.Button(utilities_frame, text="List Formats", command=lambda: self.run_jtr_utility_command("--list=formats"))
        self.list_formats_button.pack(side="left", padx=5, pady=5)
        ToolTip(self.list_formats_button, "List all hash formats supported by this John the Ripper build.")

        self.list_encodings_button = ttk.Button(utilities_frame, text="List Encodings", command=lambda: self.run_jtr_utility_command("--list=encodings"))
        self.list_encodings_button.pack(side="left", padx=5, pady=5)
        ToolTip(self.list_encodings_button, "List all text encodings supported by John.")
        
        self.clear_output_button = ttk.Button(utilities_frame, text="Clear Output", command=self.clear_output)
        self.clear_output_button.pack(side="left", padx=5, pady=5)
        ToolTip(self.clear_output_button, "Clear the output log area.")

        # --- Output Frame (in the bottom part of PanedWindow) ---
        output_frame_outer = ttk.Frame(main_paned_window) 
        main_paned_window.add(output_frame_outer, weight=1) # This part will expand

        output_frame = ttk.LabelFrame(output_frame_outer, text="Output Log", padding=(10, 5))
        output_frame.pack(padx=10, pady=0, fill="both", expand=True) 

        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15, state=tk.DISABLED, font=("Consolas", 9) if os.name == 'nt' else ("Monospace", 9))
        self.output_text.pack(fill="both", expand=True)
        # Define tags for colored output
        self.output_text.tag_config("error", foreground="red")
        self.output_text.tag_config("success", foreground="green")
        self.output_text.tag_config("info", foreground="blue")


        # --- Status Bar ---
        self.status_var = tk.StringVar()
        self.status_var.set("Idle")
        status_bar = ttk.Label(master, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.jtr_process = None
        self.style.configure("Accent.TButton", font=('Helvetica', 10, 'bold'), foreground="white", background="#0078D7")

    def find_john_executable(self):
        """Tries to find 'john' or 'john.exe' in common system PATHs or typical install locations."""
        for cmd in ["john", "john.exe"]:
            check_cmd = ['where' if os.name == 'nt' else 'which', cmd]
            try:
                process = subprocess.run(check_cmd, capture_output=True, text=True, check=True, env=os.environ)
                found_path = process.stdout.strip().split('\n')[0]
                if os.access(found_path, os.X_OK):
                    return found_path
            except (subprocess.CalledProcessError, FileNotFoundError, IndexError):
                continue # Try next command or fallback paths
        if os.name == 'nt':
            possible_paths = [
                os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "John\\run\\john.exe"),
                os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "John\\run\\john.exe"),
                "C:\\John\\run\\john.exe" 
            ]
        else: # Linux/macOS
            possible_paths = [
                "/usr/sbin/john", "/usr/local/sbin/john", "/opt/john/run/john",
                os.path.expanduser("~/john/run/john") 
            ]
        for path in possible_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
        return "john" # Default to 'john', assuming it's in PATH if not found explicitly

    def create_main_settings_tab(self):
        # John the Ripper Path
        ttk.Label(self.tab_main, text="John Executable Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.jtr_path_entry = ttk.Entry(self.tab_main, width=60)
        self.jtr_path_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.jtr_path_entry.insert(0, self.find_john_executable())
        ToolTip(self.jtr_path_entry, "Path to the John the Ripper executable (e.g., john or john.exe).")
        ttk.Button(self.tab_main, text="Browse", command=self.browse_jtr_path).grid(row=0, column=2, padx=5, pady=5)

        # Hash File Path
        ttk.Label(self.tab_main, text="Hash File:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.hash_file_entry = ttk.Entry(self.tab_main, width=60)
        self.hash_file_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ToolTip(self.hash_file_entry, "Path to the file containing password hashes to crack.")
        ttk.Button(self.tab_main, text="Browse", command=self.browse_hash_file).grid(row=1, column=2, padx=5, pady=5)

        # Wordlist Path (Optional)
        ttk.Label(self.tab_main, text="Wordlist (Optional):").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.wordlist_entry = ttk.Entry(self.tab_main, width=60)
        self.wordlist_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        ToolTip(self.wordlist_entry, "Path to a custom wordlist file (leave blank for other modes).")
        ttk.Button(self.tab_main, text="Browse", command=self.browse_wordlist).grid(row=2, column=2, padx=5, pady=5)

        # Format (Optional)
        ttk.Label(self.tab_main, text="Format (Optional):").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.format_entry = ttk.Entry(self.tab_main, width=60)
        self.format_entry.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        ToolTip(self.format_entry, "Specify hash format (e.g., nt, raw-md5, sha256crypt). Leave blank for auto-detection.")
        self.format_entry.insert(0, "") 

        self.tab_main.columnconfigure(1, weight=1)

    def create_advanced_options_tab(self):
        # Incremental Mode
        self.incremental_var = tk.BooleanVar()
        ttk.Checkbutton(self.tab_advanced, text="Incremental Mode", variable=self.incremental_var).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.incremental_mode_entry = ttk.Entry(self.tab_advanced, width=30)
        self.incremental_mode_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ToolTip(self.incremental_mode_entry, "Specify incremental mode (e.g., Alnum, Digits). Leave blank for default if checked.")

        # Cracking Rules
        self.rules_var = tk.BooleanVar()
        ttk.Checkbutton(self.tab_advanced, text="Use Cracking Rules", variable=self.rules_var).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.rules_entry = ttk.Entry(self.tab_advanced, width=30)
        self.rules_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ToolTip(self.rules_entry, "Specify rule name (e.g., KoreLogic, Dive). Leave blank for default rules if checked.")

        # Fork (Parallel Processing)
        ttk.Label(self.tab_advanced, text="Number of Forks:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.fork_entry = ttk.Entry(self.tab_advanced, width=10)
        self.fork_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        ToolTip(self.fork_entry, "Number of parallel processes to use (e.g., 4).")

        # Max Password Length
        ttk.Label(self.tab_advanced, text="Max Password Length:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.max_len_entry = ttk.Entry(self.tab_advanced, width=10)
        self.max_len_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        ToolTip(self.max_len_entry, "Maximum password length to try (e.g., 8).")

        # Custom JtR Config File
        ttk.Label(self.tab_advanced, text="Custom Config (Optional):").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.config_file_entry = ttk.Entry(self.tab_advanced, width=40)
        self.config_file_entry.grid(row=4, column=1, padx=5, pady=5, sticky="ew")
        ToolTip(self.config_file_entry, "Path to a custom john.conf file.")
        ttk.Button(self.tab_advanced, text="Browse", command=self.browse_config_file).grid(row=4, column=2, padx=5, pady=5)
        
        self.tab_advanced.columnconfigure(1, weight=1)

    def create_scanner_tab(self):
        # Directory Selection
        dir_frame = ttk.Frame(self.tab_scanner)
        dir_frame.pack(fill="x", pady=(0,10))
        ttk.Label(dir_frame, text="Directory to Scan:").pack(side="left", padx=(0,5))
        self.scan_dir_entry = ttk.Entry(dir_frame, width=50)
        self.scan_dir_entry.pack(side="left", expand=True, fill="x", padx=5)
        ToolTip(self.scan_dir_entry, "Enter or browse for the directory you want to scan for hash files.")
        ttk.Button(dir_frame, text="Browse Dir", command=self.browse_scan_directory).pack(side="left", padx=5)

        # Scan Controls
        scan_control_frame = ttk.Frame(self.tab_scanner)
        scan_control_frame.pack(fill="x", pady=5)
        self.start_scan_button = ttk.Button(scan_control_frame, text="Start Scan", command=self.start_directory_scan_thread)
        self.start_scan_button.pack(side="left", padx=5)
        ToolTip(self.start_scan_button, "Begin scanning the selected directory for potential hash files.")
        
        self.scanner_status_var = tk.StringVar()
        self.scanner_status_var.set("Scanner Idle")
        ttk.Label(scan_control_frame, textvariable=self.scanner_status_var).pack(side="left", padx=10)

        # Results Listbox
        results_frame = ttk.LabelFrame(self.tab_scanner, text="Potential Hash Files Found", padding=5)
        results_frame.pack(fill="both", expand=True, pady=5)
        
        self.scan_results_listbox = tk.Listbox(results_frame, height=10, selectmode=tk.SINGLE)
        self.scan_results_listbox.pack(side="left", fill="both", expand=True)
        ToolTip(self.scan_results_listbox, "List of files found that might contain hashes. Double-click or use button to select.")
        
        scan_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.scan_results_listbox.yview)
        scan_scrollbar.pack(side="right", fill="y")
        self.scan_results_listbox.config(yscrollcommand=scan_scrollbar.set)
        self.scan_results_listbox.bind("<Double-1>", self.use_selected_hash_file_from_scanner)


        # Use Selected File Button
        self.use_selected_button = ttk.Button(self.tab_scanner, text="Use Selected File in Main Settings", command=self.use_selected_hash_file_from_scanner)
        self.use_selected_button.pack(pady=5)
        ToolTip(self.use_selected_button, "Populate the 'Hash File' field in 'Main Settings' with the selected file.")


    def browse_jtr_path(self):
        path = filedialog.askopenfilename(title="Select John the Ripper Executable")
        if path:
            self.jtr_path_entry.delete(0, tk.END); self.jtr_path_entry.insert(0, path)

    def browse_hash_file(self):
        path = filedialog.askopenfilename(title="Select Hash File")
        if path:
            self.hash_file_entry.delete(0, tk.END); self.hash_file_entry.insert(0, path)

    def browse_wordlist(self):
        path = filedialog.askopenfilename(title="Select Wordlist File")
        if path:
            self.wordlist_entry.delete(0, tk.END); self.wordlist_entry.insert(0, path)

    def browse_config_file(self):
        path = filedialog.askopenfilename(title="Select Custom John Config File", filetypes=[("Config files", "*.conf"), ("All files", "*.*")])
        if path:
            self.config_file_entry.delete(0, tk.END); self.config_file_entry.insert(0, path)

    def browse_scan_directory(self):
        directory = filedialog.askdirectory(title="Select Directory to Scan")
        if directory:
            self.scan_dir_entry.delete(0, tk.END)
            self.scan_dir_entry.insert(0, directory)
            self.scanner_status_var.set(f"Selected: {os.path.basename(directory)}")

    def log_output(self, message, tag=None): # tag can be "error", "success", "info"
        self.output_text.config(state=tk.NORMAL)
        if tag:
            self.output_text.insert(tk.END, message + "\n", tag)
        else:
            self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.master.update_idletasks()

    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.log_output("--- Output cleared ---", "info")

    def set_buttons_state(self, running=False, scanner_active=False):
        jtr_running = running
        scan_running = scanner_active

        # JTR Controls
        self.run_button.config(state=tk.DISABLED if jtr_running or scan_running else tk.NORMAL)
        self.show_cracked_button.config(state=tk.DISABLED if jtr_running or scan_running else tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL if jtr_running else tk.DISABLED)
        
        # Utility Controls
        self.list_formats_button.config(state=tk.DISABLED if jtr_running or scan_running else tk.NORMAL)
        self.list_encodings_button.config(state=tk.DISABLED if jtr_running or scan_running else tk.NORMAL)
        
        # Scanner Controls
        if hasattr(self, 'start_scan_button'): # Check if scanner tab is initialized
            self.start_scan_button.config(state=tk.DISABLED if scan_running or jtr_running else tk.NORMAL)
            self.use_selected_button.config(state=tk.DISABLED if scan_running or jtr_running else tk.NORMAL)

        if jtr_running:
            self.status_var.set("JtR Running...")
        elif scan_running:
            self.status_var.set("Scanner Running...")
            self.scanner_status_var.set("Scanning...")
        else:
            self.status_var.set("Idle")
            if hasattr(self, 'scanner_status_var'): self.scanner_status_var.set("Scanner Idle")
            self.jtr_process = None


    def _validate_and_get_jtr_path(self):
        jtr_path = self.jtr_path_entry.get()
        if not jtr_path:
            messagebox.showerror("Error", "John executable path is required.")
            return None
        if os.path.exists(jtr_path) and os.access(jtr_path, os.X_OK): return jtr_path
        try:
            check_cmd = ['where' if os.name == 'nt' else 'which', jtr_path]
            path_process = subprocess.run(check_cmd, capture_output=True, text=True, check=True, env=os.environ)
            resolved_path = path_process.stdout.strip().split('\n')[0] 
            if os.path.exists(resolved_path) and os.access(resolved_path, os.X_OK): return resolved_path
        except (subprocess.CalledProcessError, FileNotFoundError, IndexError): pass
        messagebox.showerror("Error", f"John executable not found or not executable: {jtr_path}\nPlease provide a valid path or ensure it's in your system's PATH.")
        return None

    def start_jtr_thread(self):
        thread = threading.Thread(target=self.run_jtr, daemon=True)
        thread.start()

    def run_jtr(self):
        jtr_path = self._validate_and_get_jtr_path()
        if not jtr_path: return

        hash_file = self.hash_file_entry.get()
        if not hash_file: messagebox.showerror("Error", "Hash file is required."); return
        if not os.path.exists(hash_file): messagebox.showerror("Error", f"Hash file not found: {hash_file}"); return

        command = [jtr_path]
        # Create a session name based on the hash file's name to keep .pot files distinct
        session_name = f"jtr_gui_session_{os.path.splitext(os.path.basename(hash_file))[0]}" 
        command.append(f"--session={session_name}")

        # Main Settings
        wordlist = self.wordlist_entry.get()
        if wordlist:
            if not os.path.exists(wordlist): messagebox.showerror("Error", f"Wordlist file not found: {wordlist}"); return
            command.append(f"--wordlist={wordlist}")
        
        format_val = self.format_entry.get()
        if format_val: command.append(f"--format={format_val}")
        
        # Advanced Options
        if self.incremental_var.get(): 
            inc_mode = self.incremental_mode_entry.get()
            command.append(f"--incremental={inc_mode}" if inc_mode else "--incremental")
        
        if self.rules_var.get() and wordlist : # Rules typically used with wordlists
            rules_val = self.rules_entry.get()
            command.append(f"--rules={rules_val}" if rules_val else "--rules") # If checked but empty, use default rules
        
        fork_val = self.fork_entry.get()
        if fork_val:
            try: int(fork_val); command.append(f"--fork={fork_val}")
            except ValueError: messagebox.showerror("Error", "Number of forks must be an integer."); return
        
        max_len_val = self.max_len_entry.get()
        if max_len_val:
            try: int(max_len_val); command.append(f"--max-len={max_len_val}")
            except ValueError: messagebox.showerror("Error", "Max password length must be an integer."); return
        
        config_file = self.config_file_entry.get()
        if config_file:
            if not os.path.exists(config_file): messagebox.showerror("Error", f"Custom config file not found: {config_file}"); return
            command.append(f"--config={config_file}")
        
        command.append(hash_file) # Hash file must be the last option for JtR

        self.log_output(f"--- Starting John the Ripper ---", "info")
        self.log_output(f"Command: {' '.join(shlex.quote(c) for c in command)}")
        self.set_buttons_state(running=True)

        try:
            self.jtr_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                                text=True, bufsize=1, universal_newlines=True, 
                                                env=os.environ, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            for line in iter(self.jtr_process.stdout.readline, ''):
                self.log_output(line.strip())
                if self.jtr_process is None: # Process was stopped by user
                    self.log_output("--- John the Ripper process stopped by user. ---", "error")
                    break
            if self.jtr_process: # if not stopped by user
                self.jtr_process.wait()
                rc = self.jtr_process.returncode
                if rc == 0: self.log_output("--- John the Ripper finished successfully. ---", "success")
                else: self.log_output(f"--- John the Ripper finished with exit code: {rc} ---", "error")
        except FileNotFoundError:
            self.log_output(f"Error: John the Ripper executable not found at '{jtr_path}'.", "error")
            messagebox.showerror("Error", f"John the Ripper executable not found at '{jtr_path}'.")
        except Exception as e:
            self.log_output(f"An error occurred: {str(e)}", "error")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        finally:
            self.set_buttons_state(running=False)

    def stop_jtr_process(self):
        if self.jtr_process and self.jtr_process.poll() is None: # Check if process is running
            try:
                self.log_output("--- Attempting to stop John the Ripper... ---", "info")
                self.status_var.set("Stopping JtR...")
                self.jtr_process.terminate() # Send SIGTERM
                try:
                    self.jtr_process.wait(timeout=5) # Give it a moment
                    self.log_output("--- John the Ripper process terminated. ---", "success")
                except subprocess.TimeoutExpired:
                    self.log_output("--- John the Ripper did not terminate gracefully, forcing kill... ---", "error")
                    self.jtr_process.kill() # Send SIGKILL
                    self.log_output("--- John the Ripper process killed. ---", "success")
            except Exception as e:
                self.log_output(f"Error stopping JtR process: {e}", "error")
                messagebox.showerror("Error", f"Error stopping JtR process: {e}")
            finally:
                self.jtr_process = None # Crucial to mark as stopped
                self.set_buttons_state(running=False)
        else:
            self.log_output("--- No John the Ripper process is currently running. ---", "info")
            self.set_buttons_state(running=False) # Ensure buttons are reset

    def show_cracked_passwords_thread(self):
        thread = threading.Thread(target=self.show_cracked_passwords, daemon=True)
        thread.start()

    def show_cracked_passwords(self):
        jtr_path = self._validate_and_get_jtr_path()
        if not jtr_path: return

        hash_file = self.hash_file_entry.get()
        if not hash_file: messagebox.showerror("Error", "Hash file is required to show cracked passwords."); return
        
        command = [jtr_path, "--show"]
        config_file = self.config_file_entry.get()
        if config_file and os.path.exists(config_file): command.append(f"--config={config_file}")
        
        session_name = f"jtr_gui_session_{os.path.splitext(os.path.basename(hash_file))[0] if hash_file else 'default'}"
        command.append(f"--session={session_name}")
        
        command.append(hash_file) # Add hash_file at the end

        self.log_output(f"--- Showing Cracked Passwords for {os.path.basename(hash_file) if hash_file else 'session: ' + session_name} ---", "info")
        self.log_output(f"Command: {' '.join(shlex.quote(c) for c in command)}")
        self.set_buttons_state(running=True) 

        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                       text=True, bufsize=1, universal_newlines=True, env=os.environ,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            output_lines = []
            for line in iter(process.stdout.readline, ''):
                stripped_line = line.strip(); self.log_output(stripped_line); output_lines.append(stripped_line)
            
            process.wait()
            if process.returncode != 0 and not any("No password hashes loaded" in line for line in output_lines):
                 self.log_output(f"--- 'john --show' may have encountered an issue (exit code: {process.returncode}) ---", "error")
            
            cracked_found = any("passwords cracked" in line and "0 passwords cracked" not in line for line in output_lines)
            if not cracked_found and any("No password hashes loaded" in line for line in output_lines):
                 self.log_output("--- No password hashes loaded or no passwords cracked yet for this session/file. ---", "info")
            elif not cracked_found and not any("passwords cracked" in line for line in output_lines): # If no "X passwords cracked" line
                 self.log_output("--- No cracked passwords to show (or JtR output format unexpected). ---", "info")

        except FileNotFoundError: # Should be caught by _validate_and_get_jtr_path, but as a fallback
            self.log_output(f"Error: John the Ripper executable not found at '{jtr_path}'.", "error")
            messagebox.showerror("Error", f"John the Ripper executable not found at '{jtr_path}'.")
        except Exception as e:
            self.log_output(f"An error occurred while showing passwords: {str(e)}", "error")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        finally:
            self.set_buttons_state(running=False)

    def run_jtr_utility_command(self, utility_flag):
        jtr_path = self._validate_and_get_jtr_path()
        if not jtr_path: return
        command = [jtr_path, utility_flag]
        self.log_output(f"--- Running JtR Utility: {' '.join(shlex.quote(c) for c in command)} ---", "info")
        self.set_buttons_state(running=True)
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                       text=True, bufsize=1, universal_newlines=True, env=os.environ,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            for line in iter(process.stdout.readline, ''): self.log_output(line.strip())
            process.wait()
            if process.returncode != 0: self.log_output(f"--- JtR utility command finished with exit code: {process.returncode} ---", "error")
            else: self.log_output(f"--- JtR utility command finished successfully. ---", "success")
        except FileNotFoundError:
            self.log_output(f"Error: John the Ripper executable not found at '{jtr_path}'.", "error")
            messagebox.showerror("Error", f"John the Ripper executable not found at '{jtr_path}'.")
        except Exception as e:
            self.log_output(f"An error occurred: {str(e)}", "error")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        finally:
            self.set_buttons_state(running=False)

    # --- Hash Scanner Methods ---
    def start_directory_scan_thread(self):
        scan_dir = self.scan_dir_entry.get()
        if not scan_dir or not os.path.isdir(scan_dir):
            messagebox.showerror("Error", "Please select a valid directory to scan.")
            return
        
        self.scan_results_listbox.delete(0, tk.END) # Clear previous results
        self.log_output(f"--- Starting hash file scan in directory: {scan_dir} ---", "info")
        
        self.set_buttons_state(scanner_active=True)
        
        thread = threading.Thread(target=self.scan_directory_for_hashes, args=(scan_dir,), daemon=True)
        thread.start()

    def is_potential_hash_file(self, filepath):
        """Checks if a file is a potential hash file based on name, extension, or content."""
        filename_lower = os.path.basename(filepath).lower()
        _, ext_lower = os.path.splitext(filename_lower)

        if filename_lower in self.KNOWN_HASH_FILENAMES: return True, "Known Filename"
        if ext_lower in self.KNOWN_HASH_EXTENSIONS: return True, "Known Extension"
        for keyword in self.KEYWORDS_IN_FILENAME:
            if keyword in filename_lower: return True, f"Keyword '{keyword}'"
        
        try:
            if 0 < os.path.getsize(filepath) < 5 * 1024 * 1024: # Check non-empty files up to 5MB
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    lines_checked = 0
                    for line in f:
                        line = line.strip()
                        if not line: continue 
                        for pattern_name, pattern_re in self.HASH_PATTERNS_SAMPLE.items():
                            if pattern_re.fullmatch(line): return True, f"Content ({pattern_name})"
                        lines_checked +=1
                        if lines_checked >= self.MAX_CONTENT_CHECK_LINES: break
        except (IOError, UnicodeDecodeError, PermissionError, OSError): pass # OSError for various file issues
        except Exception: pass # Catch any other unexpected errors
            
        return False, None


    def scan_directory_for_hashes(self, scan_dir):
        found_count = 0
        try:
            for root, _, files in os.walk(scan_dir, onerror=lambda err: self.log_output(f"Scan error accessing {err.filename}: {err.strerror}", "error")):
                if not self.status_var.get().startswith("Scanner Running"): 
                    self.log_output("--- Hash scan cancelled. ---", "info")
                    break
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        # Skip if not a file or not accessible
                        if not os.path.isfile(filepath) or not os.access(filepath, os.R_OK):
                            continue
                        is_potential, reason = self.is_potential_hash_file(filepath)
                        if is_potential:
                            self.scan_results_listbox.insert(tk.END, f"{filepath} ({reason})")
                            self.scan_results_listbox.see(tk.END) 
                            found_count += 1
                            self.scanner_status_var.set(f"Scanning... Found: {found_count}")
                            self.master.update_idletasks() 
                    except Exception as e: # Catch errors during individual file processing
                        self.log_output(f"Error scanning file {filepath}: {e}", "error")
        except Exception as e: # Catch errors during os.walk itself
            self.log_output(f"Error during directory scan: {e}", "error")
            messagebox.showerror("Scan Error", f"An error occurred during scanning: {e}")
        finally:
            self.log_output(f"--- Hash file scan completed. Found {found_count} potential files. ---", "success" if found_count > 0 else "info")
            self.scanner_status_var.set(f"Scan Finished. Found: {found_count}")
            self.set_buttons_state(scanner_active=False)

    def use_selected_hash_file_from_scanner(self, event=None): 
        selected_indices = self.scan_results_listbox.curselection()
        if not selected_indices:
            messagebox.showinfo("Info", "Please select a file from the list first.")
            return
        
        selected_item_text = self.scan_results_listbox.get(selected_indices[0])
        filepath_match = re.match(r"^(.*?) \(", selected_item_text) # Extract filepath before " ("
        if not filepath_match:
            messagebox.showerror("Error", "Could not parse filepath from selected item.")
            return
        filepath = filepath_match.group(1)

        if os.path.exists(filepath):
            self.hash_file_entry.delete(0, tk.END)
            self.hash_file_entry.insert(0, filepath)
            self.log_output(f"--- Selected hash file from scanner: {filepath} ---", "success")
            self.notebook.select(self.tab_main) 
            messagebox.showinfo("File Selected", f"'{os.path.basename(filepath)}' has been set as the hash file.")
        else:
            messagebox.showerror("Error", f"File not found or path is incorrect: {filepath}")


if __name__ == '__main__':
    root = tk.Tk()
    gui = JTR_GUI_Enhanced(root)
    root.mainloop()