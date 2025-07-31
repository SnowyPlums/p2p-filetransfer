import tkinter as tk
import ttkbootstrap as ttkbs
from app import FileTransferApp

if __name__ == "__main__":
    root = ttkbs.Window()
    app = FileTransferApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.cleanup(), root.destroy()))
    root.mainloop()