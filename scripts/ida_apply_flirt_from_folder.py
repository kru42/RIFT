"""Ida python helper script, which loads a set of flirt signatures stored in a folder."""

import tkinter as tk
from tkinter import filedialog
import ida_funcs
import os


def apply_flirt(f):
    ida_funcs.plan_to_apply_idasgn(f)


def select_folder():
    root = tk.Tk()
    root.withdraw()
    folder_path = filedialog.askdirectory(title="Select a folder")
    return folder_path

# Run the function
folder = select_folder()
if not folder:
    print("[debug] No folder selected!")
else:
    for file in [os.path.join(folder, f) for f in os.listdir(folder)]:
        if file.endswith(".sig"):
            print(f"[debug] Applying flirt signature = {file}")
            apply_flirt(file)
