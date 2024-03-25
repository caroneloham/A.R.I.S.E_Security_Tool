import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
import subprocess

# Fonction pour exécuter le scan Nmap
def scan_ip():
    ip_address = ip_entry.get()
    if ip_address:
        try:
            # Exécution du scan Nmap
            result = subprocess.check_output(["nmap", "-sV", ip_address], text=True)
            # Affichage des résultats dans le widget ScrolledText
            output_text.configure(state='normal')
            output_text.delete(1.0, tk.END)
            output_text.insert(tk.INSERT, result)
            output_text.configure(state='disabled')
        except Exception as e:
            messagebox.showerror("Erreur", f"Une erreur s'est produite lors de l'exécution du scan: {e}")
    else:
        messagebox.showwarning("Attention", "Veuillez entrer une adresse IP.")

# Configuration de la fenêtre principale
root = tk.Tk()
root.title("ARISE - Nmap Scan")
root.configure(bg='#e0ffef')

# Configuration du thème de couleur
color_theme = {
    "bg": "#e0ffef",
    "fg": "#005f73",
    "button": "#00b4d8",
    "text": "#023e8a"
}

# Création des widgets
ip_label = tk.Label(root, text="Entrez l'adresse IP:", bg=color_theme["bg"], fg=color_theme["fg"])
ip_entry = tk.Entry(root, bg="white", fg="black")
scan_button = tk.Button(root, text="Scanner", command=scan_ip, bg=color_theme["button"], fg="white")
output_text = scrolledtext.ScrolledText(root, height=10, bg="white", fg="black", state='disabled')

# Placement des widgets
ip_label.pack(pady=5)
ip_entry.pack(pady=5)
scan_button.pack(pady=5)
output_text.pack(pady=5)

# Lancement de l'interface graphique
root.mainloop()
