import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import psutil
import subprocess
import re
import os
import time
import hashlib

def run_powershell_command(command):
    subprocess.run(["powershell", "-Command", command], shell=True)

def change_permission_dialog(process_id, process_name):
    dialog = tk.Toplevel(root)
    dialog.title(f"Change Permission for {process_name} (PID: {process_id})")
    dialog.geometry("300x150")

    label = tk.Label(dialog, text=f"Choose permission for {process_name}:")
    label.pack(pady=10)

    def set_permission(permission):
        if permission == "deny":
            ps_command = f"Stop-Process -Id {process_id} -Force"
            run_powershell_command(ps_command)
            print(f"Process {process_name} terminated.")
        else:
            print(f"Permission '{permission}' for {process_name} is not implemented.")
        dialog.destroy()

    allow_button = tk.Button(dialog, text="Allow", command=lambda: set_permission("allow"))
    deny_button = tk.Button(dialog, text="Deny", command=lambda: set_permission("deny"))

    allow_button.pack(side=tk.LEFT, padx=20, pady=20)
    deny_button.pack(side=tk.RIGHT, padx=20, pady=20)

def on_expand_process_details(tree):
    try:
        selected_item = tree.selection()[0]
        process_id, process_name = tree.item(selected_item, 'values')
        expand_process_dialog(process_id, process_name)
    except IndexError:
        print("No process selected. Please select a process from the list.")


def expand_process_dialog(process_id, process_name):
    dialog = tk.Toplevel(root)
    dialog.title(f"Details for {process_name} (PID: {process_id})")
    dialog.geometry("400x300")

    details_label = tk.Label(dialog, text="Fetching process details...", justify=tk.LEFT)
    details_label.pack(pady=10)

    try:
        proc = psutil.Process(int(process_id))
        info = proc.as_dict(attrs=['pid', 'name', 'memory_percent', 'cpu_percent', 'num_threads', 'exe', 'create_time'])
        info_text = "\n".join([f"{k.capitalize().replace('_', ' ')}: {v}" for k, v in info.items()])
        details_label.config(text=info_text)
    except psutil.NoSuchProcess:
        details_label.config(text=f"No process with PID {process_id} found.")
    except Exception as e:
        details_label.config(text=f"Error: {str(e)}")

def update_process_list(tree):
    """ Fetch the current list of processes and update the TreeView """
    try:
        # Clear existing entries in the TreeView
        for item in tree.get_children():
            tree.delete(item)

        # Fetch and insert new process list
        for proc in psutil.process_iter(['pid', 'name']):
            tree.insert("", 'end', values=(proc.info['pid'], proc.info['name']))
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass  # Ignore processes that have vanished or we don't have access to

def scheduled_update(tree, interval=5000):
    #Schedule the process list update at a defined interval (default 5000 ms)
    update_process_list(tree)
    root.after(interval, scheduled_update, tree, interval)  # Reschedule itself

def on_change_permission(tree):
    try:
        selected_item = tree.selection()[0]  # Get the first (and should be only) selected item
        process_id, process_name = tree.item(selected_item, 'values')
        change_permission_dialog(process_id, process_name)
    except IndexError:
        print("No process selected. Please select a process from the list.")

def extract_strings_from_exe(exe_path):
    try:
        # Run the 'strings' utility to extract all strings from the executable
        result = subprocess.run(['strings', exe_path], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            all_strings = result.stdout.split('\n')

            # Prepare regex patterns to match specific types of strings
            url_pattern = re.compile(r'https?://[^\s]+')  # URLs
            exe_pattern = re.compile(r'\b\w+\.exe\b', re.IGNORECASE)  # Executable files
            dll_pattern = re.compile(r'\b\w+\.dll\b', re.IGNORECASE)  # DLL files
            lib_pattern = re.compile(r'\b\w+\.lib\b', re.IGNORECASE)  # Library files
            cmd_pattern = re.compile(r'\b\w+\.(cmd|bat)\b', re.IGNORECASE)  # Command files

            # Filter strings based on the compiled patterns
            filtered_strings = [s for s in all_strings if url_pattern.search(s) or exe_pattern.search(s) or
                                dll_pattern.search(s) or lib_pattern.search(s) or cmd_pattern.search(s)]

            return filtered_strings
        else:
            print(f"Failed to extract strings from {exe_path}")
            return None
    except subprocess.TimeoutExpired:
        print("Timeout expired while extracting strings")
        return None

def get_process_hash(exe_path):
    hasher = hashlib.sha256()
    with open(exe_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def terminate_process(process_id):
    subprocess.run(["powershell", "-Command", f"Stop-Process -Id {process_id} -Force"], shell=True)
    print(f"Process with PID {process_id} terminated.")

def wait_for_completion(file_path, timeout=300):
    """ Wait for a file to be written indicating process completion """
    start_time = time.time()
    while True:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                content = f.read().strip()
            os.remove(file_path)  # Delete the file after reading
            if content:  # File will contain content to indicate readiness
                return content
        if (time.time() - start_time) > timeout:
            raise TimeoutError("Timeout waiting for response from main.py")
        time.sleep(1)  # Wait for 1 second before checking again

# Function to open 'main.py' and pass extracted strings for analysis
def open_main_py():
    try:
        selected_item = tree.selection()[0]  # Get the selected item/process
        process_id, process_name = tree.item(selected_item, 'values')
        proc = psutil.Process(int(process_id))
        exe_path = proc.exe()  # Get the path of the executable
        completion_file = "completion_file.txt"  # Path to the completion indicator file

        # Extract strings and hash
        filtered_strings = extract_strings_from_exe(exe_path)
        process_hash = get_process_hash(exe_path)

        if filtered_strings:
            # Combine all data into one string
            combined_data = '\n'.join(
                filtered_strings) + "\nProcess Hash (SHA-256):\n" + process_hash

            # Write the combined data to a temporary file
            with open("strings_data.txt", "w", encoding='utf-8') as f:
                f.write(combined_data)


            # Dynamically determine the path to 'main.py' in the same directory as this script
            current_dir = os.path.dirname(os.path.abspath(__file__))
            main_py_path = os.path.join(current_dir, "main.py")
            #main_py_path = r"C:\Users\rusty\Documents\Prjoect\HIPSDontLie\main.py"

            # Use the default Python executable using the PATH.
            python_executable_path = "python"

            # Run main.py and capture its output
            subprocess.Popen([python_executable_path, main_py_path], shell=True)

            # Wait for completion and get response
            response = wait_for_completion(completion_file)

            # Check if the output is "yes"
            if response.strip().lower() == "yes.":
                terminate_process(process_id)
                messagebox.showinfo("Process Terminated",
                                    f"The process {process_name} was found malicious and has been terminated.")
            else:
                messagebox.showinfo("Process Checked", f"The process {process_name} was found not malicious.")
                messagebox.showinfo("Info", "Process is not malicious.")

    except IndexError:
        messagebox.showerror("Error", "No process selected. Please select a process from the list.")
    except psutil.NoSuchProcess:
        messagebox.showerror("Error", "Process no longer exists.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open main.py: {e}")

# Main window setup
root = tk.Tk()
root.title("HIPSDontLie")
root.geometry("800x400")

# TreeView setup
tree_frame = ttk.Frame(root)
tree_frame.pack(fill=tk.BOTH, expand=True)

tree_scroll = ttk.Scrollbar(tree_frame)
tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

tree = ttk.Treeview(tree_frame, yscrollcommand=tree_scroll.set, columns=("PID", "Process Name"), show='headings')
tree.heading("PID", text="PID")
tree.heading("Process Name", text="Process Name")
tree.column("PID", width=100)
tree.column("Process Name", width=680)
tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

tree_scroll.config(command=tree.yview)

# Button to change permission for selected process
change_permission_btn = ttk.Button(root, text="Change Permission", command=lambda: on_change_permission(tree))
change_permission_btn.pack(pady=10)

# Button to expand process details
expand_details_btn = ttk.Button(root, text="Expand Process Details", command=lambda: on_expand_process_details(tree))
expand_details_btn.pack(pady=10)

expand_details_btn = ttk.Button(root, text="Check File With ChadAI", command=open_main_py)
expand_details_btn.pack(pady=10)


# Populate the process list
update_process_list(tree)
scheduled_update(tree, 5000)  # Update every 5 seconds

root.mainloop()