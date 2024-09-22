import tkinter as tk

def on_button_click():
    print("Button clicked!")

root = tk.Tk()
root.title("Hello, Tkinter!")

button = tk.Button(root, text="Click Me", command=on_button_click)
button.pack(pady=20)

root.mainloop()