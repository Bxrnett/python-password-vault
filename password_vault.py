"""
Main Password Vault GUI Application
Provides a user interface for managing passwords securely
"""
import tkinter as tk
from tkinter import ttk, messagebox
from database import Database
from encryption import PasswordEncryption
from typing import Optional


class PasswordVaultApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Vault")
        self.root.geometry("550x550")
        self.root.resizable(True, True)
        
        self.db = Database()
        self.current_user_id: Optional[int] = None
        self.current_username: Optional[str] = None
        self.encryption: Optional[PasswordEncryption] = None
        
        # Center the window
        self.center_window()
        
        # Show login screen
        self.show_login_screen()
    
    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def clear_screen(self):
        """Clear all widgets from the window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_login_screen(self):
        """Display the login/register screen"""
        self.clear_screen()
        
        # Title
        title_label = tk.Label(self.root, text="Password Vault", font=("Arial", 24, "bold"))
        title_label.pack(pady=30)
        
        # Frame for login form
        form_frame = tk.Frame(self.root)
        form_frame.pack(pady=20)
        
        # Username
        tk.Label(form_frame, text="Username:", font=("Arial", 12)).grid(row=0, column=0, pady=10, padx=10, sticky="e")
        self.username_entry = tk.Entry(form_frame, font=("Arial", 12), width=25)
        self.username_entry.grid(row=0, column=1, pady=10, padx=10)
        
        # Password
        tk.Label(form_frame, text="Master Password:", font=("Arial", 12)).grid(row=1, column=0, pady=10, padx=10, sticky="e")
        self.master_password_entry = tk.Entry(form_frame, font=("Arial", 12), width=25, show="*")
        self.master_password_entry.grid(row=1, column=1, pady=10, padx=10)
        
        # Bind Enter key to login
        self.username_entry.bind("<Return>", lambda e: self.master_password_entry.focus())
        self.master_password_entry.bind("<Return>", lambda e: self.login())
        
        # Buttons frame
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=20)
        
        login_btn = tk.Button(button_frame, text="Login", font=("Arial", 12), 
                             command=self.login, bg="#4CAF50", fg="white", 
                             padx=20, pady=5, width=10)
        login_btn.grid(row=0, column=0, padx=10)
        
        register_btn = tk.Button(button_frame, text="Register", font=("Arial", 12), 
                                command=self.register, bg="#2196F3", fg="white", 
                                padx=20, pady=5, width=10)
        register_btn.grid(row=0, column=1, padx=10)
        
        # Focus on username entry
        self.username_entry.focus()
    
    def login(self):
        """Handle user login"""
        username = self.username_entry.get().strip()
        master_password = self.master_password_entry.get()
        
        if not username or not master_password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        user_id = self.db.verify_user(username, master_password)
        
        if user_id:
            self.current_user_id = user_id
            self.current_username = username
            self.encryption = PasswordEncryption(master_password)
            self.show_vault_screen()
        else:
            messagebox.showerror("Error", "Invalid username or password")
    
    def register(self):
        """Handle user registration"""
        username = self.username_entry.get().strip()
        master_password = self.master_password_entry.get()
        
        if not username or not master_password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        if len(master_password) < 6:
            messagebox.showerror("Error", "Master password must be at least 6 characters long")
            return
        
        if self.db.create_user(username, master_password):
            messagebox.showinfo("Success", "Account created successfully! Please login.")
            self.username_entry.delete(0, tk.END)
            self.master_password_entry.delete(0, tk.END)
            self.username_entry.focus()
        else:
            messagebox.showerror("Error", "Username already exists")
    
    def show_vault_screen(self):
        """Display the main vault screen"""
        self.clear_screen()
        
        # Header
        header_frame = tk.Frame(self.root, bg="#2196F3")
        header_frame.pack(fill="x")
        
        tk.Label(header_frame, text=f"Welcome, {self.current_username}!", 
                font=("Arial", 16, "bold"), bg="#2196F3", fg="white").pack(side="left", padx=20, pady=10)
        
        logout_btn = tk.Button(header_frame, text="Logout", command=self.logout,
                              bg="#f44336", fg="white", padx=10, pady=5)
        logout_btn.pack(side="right", padx=20, pady=10)
        
        # Main content frame
        content_frame = tk.Frame(self.root)
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Add password section
        add_frame = tk.LabelFrame(content_frame, text="Add/Update Password", 
                                 font=("Arial", 12, "bold"), padx=10, pady=10)
        add_frame.pack(fill="x", pady=(0, 20))
        
        tk.Label(add_frame, text="Site Name:", font=("Arial", 10)).grid(row=0, column=0, pady=5, sticky="e")
        self.site_entry = tk.Entry(add_frame, font=("Arial", 10), width=30)
        self.site_entry.grid(row=0, column=1, pady=5, padx=10)
        
        tk.Label(add_frame, text="Password:", font=("Arial", 10)).grid(row=1, column=0, pady=5, sticky="e")
        self.password_entry = tk.Entry(add_frame, font=("Arial", 10), width=30, show="*")
        self.password_entry.grid(row=1, column=1, pady=5, padx=10)
        
        add_btn = tk.Button(add_frame, text="Add/Update", command=self.add_password,
                           bg="#4CAF50", fg="white", padx=15, pady=5)
        add_btn.grid(row=2, column=1, pady=10, sticky="e")
        
        # View passwords section
        view_frame = tk.LabelFrame(content_frame, text="Saved Passwords", 
                                  font=("Arial", 12, "bold"), padx=10, pady=10)
        view_frame.pack(fill="both", expand=True)
        
        # Listbox with scrollbar
        listbox_frame = tk.Frame(view_frame)
        listbox_frame.pack(fill="both", expand=True)
        
        scrollbar = tk.Scrollbar(listbox_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.sites_listbox = tk.Listbox(listbox_frame, font=("Arial", 10), 
                                        yscrollcommand=scrollbar.set)
        self.sites_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.sites_listbox.yview)
        
        # Buttons for viewing and deleting
        button_frame = tk.Frame(view_frame)
        button_frame.pack(fill="x", pady=(10, 0))
        
        view_btn = tk.Button(button_frame, text="View Password", command=self.view_password,
                            bg="#2196F3", fg="white", padx=15, pady=5)
        view_btn.pack(side="left", padx=5)
        
        copy_btn = tk.Button(button_frame, text="Copy Password", command=self.copy_password,
                            bg="#FF9800", fg="white", padx=15, pady=5)
        copy_btn.pack(side="left", padx=5)
        
        delete_btn = tk.Button(button_frame, text="Delete", command=self.delete_password,
                              bg="#f44336", fg="white", padx=15, pady=5)
        delete_btn.pack(side="left", padx=5)
        
        refresh_btn = tk.Button(button_frame, text="Refresh", command=self.refresh_sites,
                               bg="#9E9E9E", fg="white", padx=15, pady=5)
        refresh_btn.pack(side="right", padx=5)
        
        # Load saved sites
        self.refresh_sites()
    
    def add_password(self):
        """Add or update a password"""
        site_name = self.site_entry.get().strip()
        password = self.password_entry.get()
        
        if not site_name or not password:
            messagebox.showerror("Error", "Please enter both site name and password")
            return
        
        # Encrypt the password
        encrypted_password = self.encryption.encrypt(password)
        
        # Try to add, if it fails (duplicate), try to update
        if self.db.add_password(self.current_user_id, site_name, encrypted_password):
            messagebox.showinfo("Success", f"Password for {site_name} added successfully!")
        elif self.db.update_password(self.current_user_id, site_name, encrypted_password):
            messagebox.showinfo("Success", f"Password for {site_name} updated successfully!")
        else:
            messagebox.showerror("Error", "Failed to save password")
            return
        
        # Clear entries and refresh list
        self.site_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.refresh_sites()
    
    def refresh_sites(self):
        """Refresh the list of saved sites"""
        self.sites_listbox.delete(0, tk.END)
        sites = self.db.get_all_sites(self.current_user_id)
        for site in sites:
            self.sites_listbox.insert(tk.END, site)
    
    def view_password(self):
        """View the password for the selected site"""
        selection = self.sites_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a site from the list")
            return
        
        site_name = self.sites_listbox.get(selection[0])
        encrypted_password = self.db.get_password(self.current_user_id, site_name)
        
        if encrypted_password:
            password = self.encryption.decrypt(encrypted_password)
            messagebox.showinfo(f"Password for {site_name}", f"Password: {password}")
        else:
            messagebox.showerror("Error", "Failed to retrieve password")
    
    def copy_password(self):
        """Copy the password for the selected site to clipboard"""
        selection = self.sites_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a site from the list")
            return
        
        site_name = self.sites_listbox.get(selection[0])
        encrypted_password = self.db.get_password(self.current_user_id, site_name)
        
        if encrypted_password:
            password = self.encryption.decrypt(encrypted_password)
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Success", f"Password for {site_name} copied to clipboard!")
        else:
            messagebox.showerror("Error", "Failed to retrieve password")
    
    def delete_password(self):
        """Delete the selected password"""
        selection = self.sites_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a site from the list")
            return
        
        site_name = self.sites_listbox.get(selection[0])
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the password for {site_name}?"):
            if self.db.delete_password(self.current_user_id, site_name):
                messagebox.showinfo("Success", f"Password for {site_name} deleted successfully!")
                self.refresh_sites()
            else:
                messagebox.showerror("Error", "Failed to delete password")
    
    def logout(self):
        """Logout the current user"""
        self.current_user_id = None
        self.current_username = None
        self.encryption = None
        self.show_login_screen()
    
    def run(self):
        """Run the application"""
        self.root.mainloop()


if __name__ == "__main__":
    app = PasswordVaultApp()
    app.run()
