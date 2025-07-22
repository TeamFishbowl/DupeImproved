import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import csv
import os
import subprocess
from PIL import Image, ImageTk
import io
import threading
import sys
import hashlib
from collections import defaultdict
import time

PREVIEW_WIDTH = 240
PREVIEW_HEIGHT = 135

STARTUPINFO = None
if sys.platform == "win32":
    STARTUPINFO = subprocess.STARTUPINFO()
    STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW

APP_DIR = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__)
FFMPEG_PATH = os.path.join(APP_DIR, "ffmpeg.exe")
FFPROBE_PATH = os.path.join(APP_DIR, "ffprobe.exe")

# Supported media file extensions
MEDIA_EXTENSIONS = {
    '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v', 
    '.mpg', '.mpeg', '.3gp', '.asf', '.rm', '.rmvb', '.vob', '.ts', '.mts'
}

def format_size(num_bytes):
    try:
        size = float(num_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
    except:
        return str(num_bytes)

def calculate_file_hash(file_path, algorithm='sha256'):
    """Calculate cryptographic hash of file"""
    try:
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(8192), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception:
        return None

def calculate_perceptual_hash_lite(image_data):
    """Calculate perceptual hash using only PIL, no numpy - optimized version"""
    try:
        # Convert image to grayscale and resize to 8x8
        image = Image.open(io.BytesIO(image_data))
        image = image.convert('L').resize((8, 8), Image.Resampling.LANCZOS)
        
        # Get pixel values as list
        pixels = list(image.getdata())
        avg = sum(pixels) / len(pixels)
        
        # Create binary hash more efficiently
        binary_hash = ''.join('1' if pixel >= avg else '0' for pixel in pixels)
        
        # Convert binary to hexadecimal
        return hex(int(binary_hash, 2))[2:].zfill(16)  # Ensure consistent length
    except Exception:
        return None

def hamming_distance(hash1, hash2):
    """Calculate hamming distance between two hashes - optimized"""
    if not hash1 or not hash2 or len(hash1) != len(hash2):
        return 100  # Return high distance for invalid hashes
    
    try:
        # Convert hex to int and XOR, then count bits
        xor_result = int(hash1, 16) ^ int(hash2, 16)
        return bin(xor_result).count('1')
    except Exception:
        return 100

def scan_folder_for_media(folder_path, progress_callback=None):
    """Scan folder recursively for media files and return file data"""
    media_files = []
    total_files = 0
    processed = 0
    
    # First pass: count total files
    for root, dirs, files in os.walk(folder_path):
        total_files += len([f for f in files if any(f.lower().endswith(ext) for ext in MEDIA_EXTENSIONS)])
    
    # Second pass: collect file data
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if any(file.lower().endswith(ext) for ext in MEDIA_EXTENSIONS):
                try:
                    full_path = os.path.join(root, file)
                    file_size = os.path.getsize(full_path)
                    
                    file_data = {
                        'Name': file,
                        'Path': root,
                        'Size': file_size
                    }
                    media_files.append(file_data)
                    processed += 1
                    
                    if progress_callback and processed % 10 == 0:
                        progress_callback(processed, total_files)
                        
                except (OSError, IOError):
                    continue  # Skip files we can't access
    
    return media_files

class DupeCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Duplicate Media Checker")
        self.root.geometry("1200x700")  # Slightly larger for new controls

        self.data = []
        self.duplicates = []
        self.tree_images = {}
        self.duplicate_groups = {}  # New: Store duplicate groups for grouping
        self.sort_column = None  # New: Track current sort column
        self.sort_reverse = False  # New: Track sort direction

        self.import_cancelled = False
        self.preview_cancelled = False
        self.scan_cancelled = False

        self.status_var = tk.StringVar(value="Ready")
        self.perceptual_check_var = tk.BooleanVar(value=False)
        self.crypto_check_var = tk.BooleanVar(value=True)  # Default to True for crypto
        self.scan_mode_var = tk.StringVar(value="csv")  # csv or folder

        self.setup_gui()

    def setup_gui(self):
        style = ttk.Style(self.root)
        style.configure("Treeview", rowheight=PREVIEW_HEIGHT)

        # Main control frame
        main_control_frame = tk.Frame(self.root)
        main_control_frame.pack(fill="x", pady=5)

        # Scan mode selection
        mode_frame = tk.Frame(main_control_frame)
        mode_frame.pack(fill="x", pady=2)
        
        tk.Label(mode_frame, text="Scan Mode:", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        tk.Radiobutton(mode_frame, text="Import CSV", variable=self.scan_mode_var, 
                      value="csv", font=("Arial", 9)).pack(side="left", padx=5)
        tk.Radiobutton(mode_frame, text="Scan Folder", variable=self.scan_mode_var, 
                      value="folder", font=("Arial", 9)).pack(side="left", padx=5)

        # Action buttons frame
        btn_frame = tk.Frame(main_control_frame)
        btn_frame.pack(fill="x", pady=2)

        tk.Button(btn_frame, text="Start Scan", command=self.start_scan).pack(side="left", padx=5)
        self.cancel_scan_btn = tk.Button(btn_frame, text="Cancel Scan", command=self.cancel_scan, state="disabled")
        self.cancel_scan_btn.pack(side="left", padx=5)

        tk.Button(btn_frame, text="Generate Previews", command=self.start_generate_previews).pack(side="left", padx=5)
        self.cancel_preview_btn = tk.Button(btn_frame, text="Cancel Preview", command=self.cancel_preview, state="disabled")
        self.cancel_preview_btn.pack(side="left", padx=5)

        # Detection options frame
        options_frame = tk.Frame(self.root)
        options_frame.pack(fill="x", pady=5)
        
        # Cryptographic hash checkbox
        self.crypto_checkbox = tk.Checkbutton(
            options_frame, 
            text="Enable Cryptographic Hash Detection (finds exact file duplicates)", 
            variable=self.crypto_check_var,
            font=("Arial", 9)
        )
        self.crypto_checkbox.pack(side="left", padx=5)

        # Perceptual duplicate check frame
        perceptual_frame = tk.Frame(self.root)
        perceptual_frame.pack(fill="x", pady=2)
        
        self.perceptual_checkbox = tk.Checkbutton(
            perceptual_frame, 
            text="Enable Perceptual Duplicate Detection (finds visually similar videos)", 
            variable=self.perceptual_check_var,
            font=("Arial", 9)
        )
        self.perceptual_checkbox.pack(side="left", padx=5)
        
        # Add similarity threshold
        tk.Label(perceptual_frame, text="Similarity threshold:").pack(side="left", padx=(20, 5))
        self.similarity_var = tk.StringVar(value="10")
        similarity_entry = tk.Entry(perceptual_frame, textvariable=self.similarity_var, width=5)
        similarity_entry.pack(side="left", padx=5)
        tk.Label(perceptual_frame, text="(0-64, lower = more strict)").pack(side="left", padx=5)

        # Add progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill="x", padx=5, pady=2)

        status_label = tk.Label(self.root, textvariable=self.status_var, anchor="w")
        status_label.pack(fill="x", padx=5)

        # Create frame for treeview and scrollbars
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Modified columns to include row number
        columns = ("#", "Name", "Path", "Size", "Duration", "Match Type")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="tree headings")
        self.tree.heading("#0", text="Preview")
        self.tree.column("#0", width=PREVIEW_WIDTH, stretch=False)
        
        # Configure column headings and widths with sorting functionality
        self.tree.heading("#", text="#")
        self.tree.column("#", width=50, stretch=False, anchor="center")
        
        # Set up sortable columns
        sortable_columns = {
            "Name": ("Name", 180),
            "Path": ("Path", 180), 
            "Size": ("Size", 100),
            "Duration": ("Duration", 100),
            "Match Type": ("Match Type", 140)
        }
        
        for col, (heading, width) in sortable_columns.items():
            self.tree.heading(col, text=heading, command=lambda c=col: self.sort_treeview_column(c))
            if col == "Match Type":
                self.tree.column(col, width=width, anchor="w")
            else:
                self.tree.column(col, width=width, anchor="w")

        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        # Pack treeview and scrollbars
        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")

        # Configure grid weights
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<Button-3>", self.show_context_menu)

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="Open File Location", command=self.open_file_location)
        self.menu.add_command(label="Copy File Name", command=self.copy_file_name)

    def sort_treeview_column(self, col):
        """Sort treeview by column - NEW FEATURE #1"""
        # Toggle sort direction if clicking same column
        if self.sort_column == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_reverse = False
        
        self.sort_column = col
        
        # Get current items with their data
        items_data = []
        for item in self.tree.get_children():
            values = self.tree.item(item, "values")
            # Find the corresponding duplicate data
            name, path = values[1], values[2]
            duplicate_data = next((d for d in self.duplicates if d['Name'] == name and d['Path'] == path), None)
            if duplicate_data:
                items_data.append((item, values, duplicate_data))
        
        # Sort function based on column
        def sort_key(item_tuple):
            _, values, dup_data = item_tuple
            
            if col == "Name":
                return values[1].lower()
            elif col == "Path":
                return values[2].lower()
            elif col == "Size":
                try:
                    return float(dup_data['Size'])
                except (ValueError, KeyError):
                    return 0
            elif col == "Duration":
                duration_str = values[4]
                if duration_str == "Unknown":
                    return -1
                try:
                    # Convert HH:MM:SS or MM:SS to seconds for sorting
                    parts = duration_str.split(':')
                    if len(parts) == 3:
                        return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
                    elif len(parts) == 2:
                        return int(parts[0]) * 60 + int(parts[1])
                    else:
                        return 0
                except (ValueError, IndexError):
                    return -1
            elif col == "Match Type":
                return values[5]
            else:
                return values[1].lower()  # Default to name
        
        # Sort the items
        sorted_items = sorted(items_data, key=sort_key, reverse=self.sort_reverse)
        
        # Reorder items in treeview
        for i, (item, values, dup_data) in enumerate(sorted_items):
            # Update row number
            new_values = list(values)
            new_values[0] = str(i + 1)
            self.tree.item(item, values=new_values)
            self.tree.move(item, "", i)
        
        # Update column heading to show sort direction
        for column in ["Name", "Path", "Size", "Duration", "Match Type"]:
            if column == col:
                symbol = " ↓" if self.sort_reverse else " ↑"
                self.tree.heading(column, text=column + symbol)
            else:
                self.tree.heading(column, text=column)

    def create_duplicate_groups(self):
        """Create groups of duplicate files - NEW FEATURE #2"""
        self.duplicate_groups = {}
        group_id = 0
        processed_files = set()
        
        for duplicate in self.duplicates:
            file_id = (duplicate['Name'], duplicate['Path'])
            if file_id in processed_files:
                continue
            
            # Find all files that match this one
            match_type = duplicate.get('MatchType', 'Unknown')
            group_files = []
            
            if 'Cryptographic' in match_type:
                # Group by file hash
                full_path = os.path.join(duplicate['Path'], duplicate['Name'])
                if os.path.isfile(full_path):
                    target_hash = calculate_file_hash(full_path, 'sha256')
                    if target_hash:
                        for other_dup in self.duplicates:
                            other_id = (other_dup['Name'], other_dup['Path'])
                            if other_id not in processed_files:
                                other_full_path = os.path.join(other_dup['Path'], other_dup['Name'])
                                if os.path.isfile(other_full_path):
                                    other_hash = calculate_file_hash(other_full_path, 'sha256')
                                    if other_hash == target_hash:
                                        group_files.append(other_dup)
                                        processed_files.add(other_id)
            
            elif 'Size-based' in match_type:
                # Group by file size
                target_size = duplicate['Size']
                for other_dup in self.duplicates:
                    other_id = (other_dup['Name'], other_dup['Path'])
                    if other_id not in processed_files and other_dup['Size'] == target_size:
                        if other_dup.get('MatchType', '') == 'Size-based':
                            group_files.append(other_dup)
                            processed_files.add(other_id)
            
            elif 'Perceptual' in match_type:
                # Group by perceptual similarity
                full_path = os.path.join(duplicate['Path'], duplicate['Name'])
                timecode = duplicate.get('Timecode', '00:00:01')
                target_hash = self.get_perceptual_hash(full_path, timecode)
                
                if target_hash:
                    threshold = 10  # Use same threshold as detection
                    try:
                        threshold = int(self.similarity_var.get())
                    except:
                        pass
                    
                    group_files.append(duplicate)
                    processed_files.add(file_id)
                    
                    for other_dup in self.duplicates:
                        other_id = (other_dup['Name'], other_dup['Path'])
                        if other_id not in processed_files and 'Perceptual' in other_dup.get('MatchType', ''):
                            other_full_path = os.path.join(other_dup['Path'], other_dup['Name'])
                            other_timecode = other_dup.get('Timecode', '00:00:01')
                            other_hash = self.get_perceptual_hash(other_full_path, other_timecode)
                            
                            if other_hash and hamming_distance(target_hash, other_hash) <= threshold:
                                group_files.append(other_dup)
                                processed_files.add(other_id)
            
            # If we couldn't group by specific method, add single file
            if not group_files:
                group_files = [duplicate]
                processed_files.add(file_id)
            
            if group_files:
                self.duplicate_groups[group_id] = group_files
                group_id += 1
    def show_context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.menu.post(event.x_root, event.y_root)

    def copy_file_name(self):
        selected = self.tree.selection()
        if not selected:
            return
        item = selected[0]
        name = self.tree.item(item, "values")[1]  # Changed index from 0 to 1 due to new # column
        self.root.clipboard_clear()
        self.root.clipboard_append(name)
        self.status_var.set(f"Copied to clipboard: {name}")

    def open_file_location(self):
        selected = self.tree.selection()
        if not selected:
            return
        item = selected[0]
        values = self.tree.item(item, "values")
        if len(values) < 3:  # Changed from 2 to 3 due to new # column
            messagebox.showwarning("Warning", "Invalid file data")
            return
        path = values[2]  # Changed index from 1 to 2 due to new # column
        name = values[1]  # Changed index from 0 to 1 due to new # column
        full_path = os.path.join(path, name)
        if os.path.exists(full_path):
            if sys.platform == "win32":
                subprocess.run(['explorer', '/select,', full_path])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", full_path])
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(full_path)])
        else:
            messagebox.showwarning("Warning", "Path does not exist")

    def start_scan(self):
        """Start either CSV import or folder scan based on selected mode"""
        if self.scan_cancelled == False and self.scan_thread_is_alive():
            messagebox.showinfo("Info", "Scan already running")
            return
            
        if self.scan_mode_var.get() == "csv":
            self.start_csv_import()
        else:
            self.start_folder_scan()

    def start_csv_import(self):
        """Start CSV import process"""
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return
        self.prepare_scan()
        self.scan_thread = threading.Thread(target=self.import_csv_worker, args=(file_path,), daemon=True)
        self.scan_thread.start()

    def start_folder_scan(self):
        """Start folder scan process"""
        folder_path = filedialog.askdirectory(title="Select folder to scan for media files")
        if not folder_path:
            return
        self.prepare_scan()
        self.scan_thread = threading.Thread(target=self.scan_folder_worker, args=(folder_path,), daemon=True)
        self.scan_thread.start()

    def prepare_scan(self):
        """Prepare UI for scanning"""
        self.scan_cancelled = False
        self.cancel_scan_btn.config(state="normal")
        self.status_var.set("Starting scan...")
        self.progress_var.set(0)
        self.data.clear()
        self.duplicates.clear()
        self.duplicate_groups.clear()  # Clear duplicate groups
        self.tree_images.clear()
        # Reset sort state
        self.sort_column = None
        self.sort_reverse = False
        for item in self.tree.get_children():
            self.tree.delete(item)

    def scan_thread_is_alive(self):
        return hasattr(self, "scan_thread") and self.scan_thread.is_alive()

    def cancel_scan(self):
        if self.scan_thread_is_alive():
            self.scan_cancelled = True
            self.status_var.set("Cancelling scan...")
            self.cancel_scan_btn.config(state="disabled")

    def scan_folder_worker(self, folder_path):
        """Worker thread for folder scanning"""
        try:
            # Scan folder for media files
            def progress_callback(processed, total):
                if self.scan_cancelled:
                    return
                progress = min((processed / total) * 30, 30)  # First 30% for file discovery
                self.root.after(0, lambda: (
                    self.status_var.set(f"Found {processed}/{total} media files..."),
                    self.progress_var.set(progress)
                ))

            media_files = scan_folder_for_media(folder_path, progress_callback)
            
            if self.scan_cancelled:
                self.finalize_scan_cancelled()
                return

            if not media_files:
                self.root.after(0, lambda: messagebox.showinfo("Info", "No media files found in the selected folder."))
                self.finalize_scan_cancelled()
                return

            # Convert to the expected format and add to self.data
            for file_data in media_files:
                self.data.append(file_data)

            self.root.after(0, lambda: (
                self.status_var.set(f"Found {len(media_files)} media files. Processing..."),
                self.progress_var.set(30)
            ))

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to scan folder:\n{e}"))
            self.finalize_scan_cancelled()
            return

        # Continue with duplicate detection
        self.process_duplicates()

    def import_csv_worker(self, file_path):
        """Worker thread for CSV import"""
        try:
            # Count total rows first for progress tracking
            with open(file_path, 'r', encoding='utf-8') as f:
                total_rows = sum(1 for _ in f) - 1  # Subtract header row
            
            with open(file_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for i, row in enumerate(reader):
                    if self.scan_cancelled:
                        self.finalize_scan_cancelled()
                        return
                    try:
                        row['Size'] = float(row['Size'])
                        row['Name'] = row['Name'].strip()
                        row['Path'] = row['Path'].strip()
                    except (ValueError, KeyError):
                        continue
                    self.data.append(row)
                    if i % 100 == 0:
                        progress = min((i / total_rows) * 30, 30)  # First 30% for import
                        self.root.after(0, lambda i=i, p=progress: (
                            self.status_var.set(f"Imported {i} rows..."),
                            self.progress_var.set(p)
                        ))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to import CSV:\n{e}"))
            self.finalize_scan_cancelled()
            return

        self.root.after(0, lambda: self.progress_var.set(30))
        # Continue with duplicate detection
        self.process_duplicates()

    def process_duplicates(self):
        """Process duplicates using selected methods"""
        all_duplicates = []
        
        # Cryptographic hash detection
        if self.crypto_check_var.get():
            self.root.after(0, lambda: self.status_var.set("Finding cryptographic duplicates..."))
            crypto_duplicates = self.find_cryptographic_duplicates()
            all_duplicates.extend(crypto_duplicates)

        # Size-based detection (fallback if crypto is disabled)
        if not self.crypto_check_var.get():
            self.root.after(0, lambda: self.status_var.set("Finding size-based duplicates..."))
            size_duplicates = self.find_size_duplicates()
            all_duplicates.extend(size_duplicates)

        self.root.after(0, lambda: self.progress_var.set(60))

        # Get duration and timecode for duplicates
        self.root.after(0, lambda: self.status_var.set("Processing duplicate metadata..."))
        for i, d in enumerate(all_duplicates):
            if self.scan_cancelled:
                return
            d['Duration'], d['Timecode'] = self.get_duration_and_timecode(d['Path'], d['Name'])
            if i % 10 == 0:
                progress = 60 + ((i / len(all_duplicates)) * 15)
                self.root.after(0, lambda i=i, p=progress: (
                    self.status_var.set(f"Processed metadata: {i}/{len(all_duplicates)}..."),
                    self.progress_var.set(p)
                ))

        # Perceptual detection
        perceptual_duplicates = []
        if self.perceptual_check_var.get():
            self.root.after(0, lambda: self.progress_var.set(75))

            # Show time estimate
            candidates = [d for d in self.data if not hasattr(d, 'MatchType')]
            estimate = self.estimate_perceptual_processing_time(len(candidates))
            self.root.after(0, lambda: self.status_var.set(f"Starting perceptual detection. Estimated time: {estimate}"))
            time.sleep(3)  # Let user see the estimate
    
            perceptual_duplicates = self.find_perceptual_duplicates()

        # Combine all duplicates
        all_duplicate_ids = set(map(id, all_duplicates)) | set(map(id, perceptual_duplicates))
        self.duplicates = [d for d in self.data if id(d) in all_duplicate_ids]

        # Create duplicate groups - NEW FEATURE #2
        self.create_duplicate_groups()

        self.finalize_scan_success(all_duplicates, perceptual_duplicates)

    def find_cryptographic_duplicates(self):
        """Find duplicates using cryptographic hashing"""
        hash_map = defaultdict(list)
        duplicates = []
        
        total_files = len(self.data)
        for i, d in enumerate(self.data):
            if self.scan_cancelled:
                return []
                
            full_path = os.path.join(d['Path'], d['Name'])
            if os.path.isfile(full_path):
                file_hash = calculate_file_hash(full_path, 'sha256')
                if file_hash:
                    hash_map[file_hash].append(d)
            
            if i % 10 == 0:
                progress = 30 + ((i / total_files) * 25)
                self.root.after(0, lambda i=i, p=progress: (
                    self.status_var.set(f"Calculating hashes: {i}/{total_files}..."),
                    self.progress_var.set(p)
                ))
        
        # Find files with matching hashes
        for file_hash, files in hash_map.items():
            if len(files) > 1:
                for file_data in files:
                    file_data['MatchType'] = 'Cryptographic'
                    duplicates.append(file_data)
        
        return duplicates

    def find_size_duplicates(self):
        """Find duplicates by file size (fallback method)"""
        size_map = defaultdict(list)
        for d in self.data:
            size_map[d['Size']].append(d)

        duplicates = []
        for files in size_map.values():
            if len(files) > 1:
                for file_data in files:
                    file_data['MatchType'] = 'Size-based'
                    duplicates.append(file_data)
        
        return duplicates

    def finalize_scan_success(self, exact_duplicates, perceptual_duplicates):
        """Finalize successful scan"""
        self.root.after(0, lambda: self.progress_var.set(95))
        self.root.after(0, self.populate_treeview)
        
        exact_count = len(exact_duplicates)
        perceptual_count = len(perceptual_duplicates)
        total_count = len(self.duplicates)
        
        # Create status message based on enabled detection methods
        status_parts = []
        if self.crypto_check_var.get():
            status_parts.append(f"{exact_count} cryptographic duplicates")
        else:
            status_parts.append(f"{exact_count} size-based duplicates")
            
        if perceptual_count > 0:
            status_parts.append(f"{perceptual_count} perceptual duplicates")
        
        status_msg = f"Scan complete. {', '.join(status_parts)} ({total_count} total)"
        
        self.root.after(0, lambda: self.progress_var.set(100))
        self.root.after(0, lambda: self.status_var.set(status_msg))
        self.root.after(0, lambda: self.cancel_scan_btn.config(state="disabled"))
        
        # Clear progress bar after 2 seconds
        self.root.after(2000, lambda: self.progress_var.set(0))

    def finalize_scan_cancelled(self):
        """Finalize cancelled scan"""
        self.root.after(0, lambda: self.status_var.set("Scan cancelled"))
        self.root.after(0, lambda: self.cancel_scan_btn.config(state="disabled"))
        self.root.after(0, lambda: self.progress_var.set(0))

    def find_perceptual_duplicates(self):
        """Find perceptually similar videos using frame hashing - IMPROVED VERSION"""
    try:
        threshold = int(self.similarity_var.get())
        if threshold < 0 or threshold > 64:
            threshold = 10
    except (ValueError, AttributeError):
        threshold = 10

    # Filter out files that are already marked as duplicates and check file existence
    candidates = []
    for d in self.data:
        if hasattr(d, 'MatchType'):
            continue
        full_path = os.path.join(d['Path'], d['Name'])
        if os.path.isfile(full_path):
            candidates.append(d)

    if not candidates:
        return []

    # Calculate perceptual hashes with better progress tracking
    hash_to_files = defaultdict(list)
    failed_files = 0
    
    for i, d in enumerate(candidates):
        if self.scan_cancelled:
            return []
        
        # Get duration and timecode if not already set
        if 'Duration' not in d:
            d['Duration'], d['Timecode'] = self.get_duration_and_timecode(d['Path'], d['Name'])
        
        # Extract frame and calculate hash
        full_path = os.path.join(d['Path'], d['Name'])
        frame_hash = self.get_perceptual_hash(full_path, d.get('Timecode', '00:00:01'))
        
        if frame_hash:
            hash_to_files[frame_hash].append(d)
        else:
            failed_files += 1
        
        # Update progress MORE FREQUENTLY - every file instead of every 25
        progress = 75 + ((i + 1) / len(candidates)) * 20
        self.root.after(0, lambda p=progress, current=i+1, total=len(candidates), failed=failed_files: (
            self.status_var.set(f"Perceptual hashes: {current}/{total} ({failed} failed)"),
            self.progress_var.set(p)
        ))
        
        # IMPORTANT: Add a small delay to prevent UI freezing but allow cancellation
        if i % 50 == 0:  # Every 50 files, give UI a chance to update
            time.sleep(0.01)
            
        # Log progress to console for debugging (remove in production)
        if i % 100 == 0:
            print(f"Processed {i}/{len(candidates)} files for perceptual hashing")

    # Update status before similarity comparison
    self.root.after(0, lambda: self.status_var.set("Comparing perceptual hashes for duplicates..."))
    
    # Find similar hashes using OPTIMIZED comparison - avoid O(n²) when possible
    perceptual_duplicates = []
    processed_files = set()
    
    # First, handle exact hash matches (these are fast)
    exact_matches = 0
    for file_hash, files in hash_to_files.items():
        if len(files) > 1:
            for file_data in files:
                if id(file_data) not in processed_files:
                    file_data['MatchType'] = 'Perceptual (Exact)'
                    perceptual_duplicates.append(file_data)
                    processed_files.add(id(file_data))
            exact_matches += len(files)

    # Show intermediate results
    if exact_matches > 0:
        self.root.after(0, lambda: self.status_var.set(f"Found {exact_matches} exact perceptual matches. Checking similar hashes..."))

    # Then, find similar hashes (only if threshold > 0) with better progress tracking
    if threshold > 0:
        hash_list = list(hash_to_files.keys())
        total_comparisons = len(hash_list) * (len(hash_list) - 1) // 2
        completed_comparisons = 0
        
        # Add comparison count warning
        if total_comparisons > 1000000:  # 1 million comparisons
            print(f"Warning: {total_comparisons} hash comparisons needed. This may take a while.")
            self.root.after(0, lambda: self.status_var.set(f"Warning: {total_comparisons} comparisons needed. This may take several minutes..."))
            time.sleep(2)  # Give user time to see the warning
        
        for i, hash1 in enumerate(hash_list):
            if self.scan_cancelled:
                break
                
            similar_group = []
            files1 = [f for f in hash_to_files[hash1] if id(f) not in processed_files]
            if files1:
                similar_group.extend(files1)
            
            for j in range(i + 1, len(hash_list)):
                hash2 = hash_list[j]
                distance = hamming_distance(hash1, hash2)
                completed_comparisons += 1
                
                if distance <= threshold:
                    files2 = [f for f in hash_to_files[hash2] if id(f) not in processed_files]
                    similar_group.extend(files2)
                
                # Update progress every 1000 comparisons
                if completed_comparisons % 1000 == 0:
                    comp_progress = (completed_comparisons / total_comparisons) * 100
                    self.root.after(0, lambda cp=comp_progress, cc=completed_comparisons, tc=total_comparisons: 
                        self.status_var.set(f"Comparing hashes: {cc}/{tc} ({cp:.1f}%)"))
                    time.sleep(0.001)  # Tiny delay to allow UI updates
            
            # Mark similar files as perceptual duplicates
            if len(similar_group) > 1:
                for file_data in similar_group:
                    if id(file_data) not in processed_files:
                        file_data['MatchType'] = 'Perceptual'
                        perceptual_duplicates.append(file_data)
                        processed_files.add(id(file_data))

    return perceptual_duplicates

    def get_perceptual_hash(self, full_path, timecode):
    """Extract a frame from video and calculate perceptual hash - with better error handling"""
    try:
        ffmpeg_cmd = [
            FFMPEG_PATH, "-ss", timecode, "-i", full_path, "-frames:v", "1",
            "-f", "image2pipe", "-vcodec", "mjpeg", "-q:v", "5", "-"
        ]
        
        # IMPORTANT: Increase timeout for large files
        image_data = subprocess.check_output(
            ffmpeg_cmd, 
            stderr=subprocess.DEVNULL, 
            startupinfo=STARTUPINFO,
            timeout=30  # Increased from 10 to 30 seconds
        )
        return calculate_perceptual_hash_lite(image_data)
    except subprocess.TimeoutExpired:
        print(f"Timeout extracting frame from: {full_path}")
        return None
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error extracting frame from {full_path}: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error with {full_path}: {e}")
        return None

        # OPTIONAL: Add a method to estimate processing time
    def estimate_perceptual_processing_time(self, file_count):
    """Estimate how long perceptual processing will take"""
    # Rough estimates based on typical performance
    hash_time_per_file = 3  # seconds per file for FFmpeg extraction
    total_hash_time = file_count * hash_time_per_file
    
    # Comparison time depends on threshold and file count
    if self.perceptual_check_var.get() and int(self.similarity_var.get()) > 0:
        comparisons = file_count * (file_count - 1) // 2
        comparison_time = comparisons * 0.0001  # Very rough estimate
        total_time = total_hash_time + comparison_time
    else:
        total_time = total_hash_time
    
    # Convert to human readable
    if total_time < 60:
        return f"~{int(total_time)} seconds"
    elif total_time < 3600:
        return f"~{int(total_time // 60)} minutes"
    else:
        return f"~{int(total_time // 3600)} hours, {int((total_time % 3600) // 60)} minutes"

    def populate_treeview(self):
        """Populate treeview with grouped duplicates - ENHANCED FOR FEATURE #2"""
        # Clear existing items efficiently
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.tree_images.clear()
        
        # Create grouped display list
        grouped_duplicates = []
        
        # Sort groups by first file's name to maintain some consistency
        sorted_groups = sorted(self.duplicate_groups.items(), 
                             key=lambda x: x[1][0]['Name'].lower())
        
        # Add each group to the display list
        for group_id, group_files in sorted_groups:
            # Sort files within group by name for consistency
            sorted_group_files = sorted(group_files, key=lambda x: x['Name'].lower())
            grouped_duplicates.extend(sorted_group_files)
        
        # Insert new items with row numbers
        for i, d in enumerate(grouped_duplicates, 1):
            match_type = d.get('MatchType', 'Unknown')
            self.tree.insert("", tk.END, text="", image="", values=(
                i,  # Row number
                d['Name'],
                d['Path'],
                format_size(d['Size']),
                d.get('Duration', 'Unknown'),
                match_type
            ))

    def start_generate_previews(self):
        if not self.duplicates:
            messagebox.showinfo("Info", "No duplicates loaded to generate previews.")
            return
        if self.preview_cancelled == False and hasattr(self, "preview_thread") and self.preview_thread.is_alive():
            messagebox.showinfo("Info", "Preview generation already running")
            return
        self.preview_cancelled = False
        self.cancel_preview_btn.config(state="normal")
        self.status_var.set("Starting preview generation...")
        self.progress_var.set(0)
        self.preview_thread = threading.Thread(target=self.generate_previews_worker, daemon=True)
        self.preview_thread.start()

    def cancel_preview(self):
        if hasattr(self, "preview_thread") and self.preview_thread.is_alive():
            self.preview_cancelled = True
            self.status_var.set("Cancelling preview generation...")
            self.cancel_preview_btn.config(state="disabled")

    def generate_previews_worker(self):
        items = self.tree.get_children()
        total = len(items)
        for i, item in enumerate(items):
            if self.preview_cancelled:
                self.root.after(0, lambda: self.status_var.set(f"Preview generation cancelled at {i}/{total}"))
                self.root.after(0, lambda: self.cancel_preview_btn.config(state="disabled"))
                self.root.after(0, lambda: self.progress_var.set(0))
                return
            values = self.tree.item(item, "values")
            name, path = values[1], values[2]  # Updated indices due to new # column
            full_path = os.path.join(path, name)
            timecode = next((d['Timecode'] for d in self.duplicates if d['Name'] == name and d['Path'] == path), "00:00:01")
            img = self.get_preview_image(full_path, timecode)
            if img:
                self.tree_images[item] = img
                self.root.after(0, lambda i=item, photo=img: self.tree.item(i, image=photo))
            
            progress = ((i + 1) / total) * 100
            self.root.after(0, lambda i=i, p=progress: (
                self.status_var.set(f"Generated previews: {i+1}/{total}"),
                self.progress_var.set(p)
            ))
        
        self.root.after(0, lambda: self.status_var.set("Preview generation completed"))
        self.root.after(0, lambda: self.cancel_preview_btn.config(state="disabled"))
        self.root.after(2000, lambda: self.progress_var.set(0))

    def get_duration_and_timecode(self, path, filename):
        full_path = os.path.join(path, filename)
        if not os.path.isfile(full_path):
            return "Unknown", "00:00:01"
        try:
            duration_raw = subprocess.check_output([
                FFPROBE_PATH, "-v", "error", "-select_streams", "v:0",
                "-show_entries", "format=duration", "-of", "default=noprint_wrappers=1:nokey=1",
                full_path
            ], stderr=subprocess.DEVNULL, startupinfo=STARTUPINFO, timeout=5).decode().strip()
            total_seconds = int(float(duration_raw))
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            seconds = total_seconds % 60
            duration = f"{hours:02}:{minutes:02}:{seconds:02}" if hours > 0 else f"{minutes:02}:{seconds:02}"
            half = total_seconds // 2
            hh, mm, ss = half // 3600, (half % 3600) // 60, half % 60
            return duration, f"{hh:02}:{mm:02}:{ss:02}"
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError):
            return "Unknown", "00:00:01"

    def get_preview_image(self, full_path, timecode):
        try:
            ffmpeg_cmd = [
                FFMPEG_PATH, "-ss", timecode, "-i", full_path, "-frames:v", "1",
                "-f", "image2pipe", "-vcodec", "mjpeg", "-q:v", "5", "-"
            ]
            image_data = subprocess.check_output(
                ffmpeg_cmd, 
                stderr=subprocess.DEVNULL, 
                startupinfo=STARTUPINFO,
                timeout=10
            )
            image = Image.open(io.BytesIO(image_data))
            image = image.resize((PREVIEW_WIDTH, PREVIEW_HEIGHT), Image.Resampling.LANCZOS)
            return ImageTk.PhotoImage(image)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return None

if __name__ == "__main__":
    root = tk.Tk()
    app = DupeCheckerApp(root)
    root.mainloop()