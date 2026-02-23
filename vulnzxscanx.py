import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
from threading import Thread
import os
import sys
from core.scanner import ScannerCore, SCAN_COMMANDS

class VulnzxScanXGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VulnzxScanX - GUI")
        self.root.geometry("750x650")
        self.root.configure(bg="#1E1E1E")
        
        self.scanner = ScannerCore()
        self.setup_ui()

    def setup_ui(self):
        # Dark Theme Styling
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TCombobox", fieldbackground="#2E2E2E", background="#444444", foreground="white")
        
        # Target Input
        tk.Label(self.root, text="Target:", fg="white", bg="#1E1E1E", font=("Arial", 10, "bold")).grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.target_entry = tk.Entry(self.root, width=50, bg="#2E2E2E", fg="white", insertbackground="white")
        self.target_entry.grid(row=0, column=1, padx=10, pady=10)
        
        load_file_button = tk.Button(self.root, text="Load File", command=self.load_targets_from_file, bg="#444444", fg="white")
        load_file_button.grid(row=0, column=2, padx=10, pady=10)

        # Output File Input
        tk.Label(self.root, text="Output File:", fg="white", bg="#1E1E1E", font=("Arial", 10, "bold")).grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.output_file_entry = tk.Entry(self.root, width=50, bg="#2E2E2E", fg="white", insertbackground="white")
        self.output_file_entry.grid(row=1, column=1, padx=10, pady=10)
        self.output_file_entry.insert(0, "scan_results.txt")

        # Scan Type
        tk.Label(self.root, text="Scan Type:", fg="white", bg="#1E1E1E", font=("Arial", 10, "bold")).grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.scan_type_var = tk.StringVar()
        self.scan_type_dropdown = ttk.Combobox(self.root, textvariable=self.scan_type_var, values=list(SCAN_COMMANDS.keys()), state="readonly")
        self.scan_type_dropdown.grid(row=2, column=1, padx=10, pady=10, sticky="w")
        self.scan_type_dropdown.set("Quick")

        # Options
        self.rotate_var = tk.BooleanVar()
        self.rotate_check = tk.Checkbutton(self.root, text="Rotate IP (Tor)", variable=self.rotate_var, bg="#1E1E1E", fg="white", selectcolor="#2E2E2E", activebackground="#1E1E1E", activeforeground="white")
        self.rotate_check.grid(row=2, column=1, padx=200, pady=10, sticky="w")

        # Buttons
        btn_frame = tk.Frame(self.root, bg="#1E1E1E")
        btn_frame.grid(row=3, column=0, columnspan=3, pady=15)

        self.start_button = tk.Button(btn_frame, text="Start Scan", command=self.start_scan, bg="#008000", fg="white", width=15)
        self.start_button.pack(side=tk.LEFT, padx=10)
        
        self.stop_button = tk.Button(btn_frame, text="Stop Scan", command=self.stop_scan, bg="#FF0000", fg="white", width=15, state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=10)
        
        self.clear_button = tk.Button(btn_frame, text="Clear Output", command=self.clear_output, bg="#444444", fg="white", width=15)
        self.clear_button.pack(side=tk.LEFT, padx=10)

        # Output text box
        self.output_text = scrolledtext.ScrolledText(self.root, height=20, width=85, bg="#2E2E2E", fg="white", font=("Consolas", 10))
        self.output_text.grid(row=4, column=0, columnspan=3, padx=15, pady=10)
        
        self.status_label = tk.Label(self.root, text="Status: Idle", fg="#00d2ff", bg="#1E1E1E", font=("Arial", 10, "italic"))
        self.status_label.grid(row=5, column=0, columnspan=3, pady=5)

    def load_targets_from_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, "r") as file:
                    targets = file.read().splitlines()
                    self.target_entry.delete(0, tk.END)
                    self.target_entry.insert(0, ", ".join(targets))
            except Exception as e:
                messagebox.showerror("File Error", f"Could not load file: {e}")

    def clear_output(self):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled")

    def update_output(self, text):
        self.output_text.config(state="normal")
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.config(state="disabled")

    def start_scan(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target.")
            return

        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.status_label.config(text="Status: Running Scan...")
        
        Thread(target=self.run_scanner_thread, args=(target,)).start()

    def run_scanner_thread(self, target):
        scan_type = self.scan_type_var.get()
        output_file = self.output_file_entry.get()
        
        if self.rotate_var.get():
            self.update_output("[*] Rotating IP...\n")
            self.scanner.rotate_ip()

        command = SCAN_COMMANDS[scan_type](target)
        
        try:
            with open(output_file, "a") as f:
                for line in self.scanner.run_scan(command, target):
                    self.update_output(line)
                    f.write(line)
                    f.flush()
        except Exception as e:
            self.update_output(f"\n[!] Error: {e}\n")
        finally:
            self.status_label.config(text="Status: Completed")
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")

    def stop_scan(self):
        if self.scanner.stop_scan():
            self.status_label.config(text="Status: Stopped")
            self.update_output("\n[!] Scan stopped by user.\n")
        else:
            messagebox.showinfo("Scanner", "No active scan found to stop.")

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnzxScanXGUI(root)
    root.mainloop()
