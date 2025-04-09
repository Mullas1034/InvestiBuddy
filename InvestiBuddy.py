import tkinter as tk
from tkinter import ttk
from IPinfo import *


def on_submit():
    # Get user inputs
    ip = abuseIPdb(entry1.get())
    sig = detect_hash_type(entry2.get())

    if sig:
        ProcData, SingerData, FtypeData, sig, ratio = ProcessInfo(entry2.get())
        result = google_api_hash(ProcData, SingerData, ip, FtypeData, sig, ratio)
    else:
        #run different prompt
        result = google_api_name(entry2.get(), ip)

    # Display the output in the text widget
    text_widget.delete("1.0", tk.END)  # Clear previous text
    text_widget.insert(tk.END, result)


def copy_to_clipboard():
    text_content = text_widget.get("1.0", tk.END)  # Get all text from the widget
    root.clipboard_clear()
    root.clipboard_append(text_content.strip())  # Strip to remove trailing newlines
    root.update()

def detect_hash_type(user_input):
    """Identify whether the input is an MD5, SHA-1, or SHA-256 hash."""
    hash_patterns = {
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA1": r"^[a-fA-F0-9]{40}$",
        "SHA256": r"^[a-fA-F0-9]{64}$"
    }

    for hash_type, pattern in hash_patterns.items():
        if re.fullmatch(pattern, user_input):
            return user_input  # Return the identified hash type

    return None  # Return None if input is not a hash


# Create the main window
root = tk.Tk()
root.title("InvestiBuddy")
root.geometry("600x400")  # Set initial window size

# Configure grid layout to be responsive
root.columnconfigure(0, weight=1)  # Make column stretchable
root.rowconfigure(3, weight=1)  # Make text widget row stretchable

# Input Field 1 (IP)
label1 = ttk.Label(root, text="IP:")
label1.grid(row=0, column=0, sticky="w", padx=10, pady=5)
entry1 = ttk.Entry(root)
entry1.grid(row=0, column=1, sticky="ew", padx=10, pady=5)
root.columnconfigure(1, weight=1)  # Make entry field stretchable

# Input Field 2 (Process Name)
label2 = ttk.Label(root, text="Process Name:")
label2.grid(row=1, column=0, sticky="w", padx=10, pady=5)
entry2 = ttk.Entry(root)
entry2.grid(row=1, column=1, sticky="ew", padx=10, pady=5)

# Submit Button
submit_button = ttk.Button(root, text="Submit", command=on_submit)
submit_button.grid(row=2, column=0, columnspan=2, pady=10)

# Output Display (Text Widget)
text_widget = tk.Text(root, height=5, wrap="word")
text_widget.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)
root.rowconfigure(3, weight=2)  # Allow text widget to expand vertically

# Copy to Clipboard Button
copy_button = ttk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.grid(row=4, column=0, columnspan=2, pady=5)

# Run the application
root.mainloop()

