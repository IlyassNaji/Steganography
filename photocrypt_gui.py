import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import os
from photocrypt import embed_message_in_image, extract_message_from_image

class PhotocryptGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Photocrypt Steganography (AES Encrypted)")
        self.root.geometry("1000x700")
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Use clam theme as base
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabelframe', background='#f0f0f0')
        self.style.configure('TLabelframe.Label', background='#f0f0f0', font=('Helvetica', 10, 'bold'))
        self.style.configure('TButton', font=('Helvetica', 9))
        self.style.configure('TLabel', background='#f0f0f0', font=('Helvetica', 9))
        self.style.configure('Status.TLabel', background='#e0e0e0', font=('Helvetica', 9))
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Image previews
        self.preview_frame = ttk.LabelFrame(self.main_frame, text="Image Preview", padding="5")
        self.preview_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Original image preview
        self.original_frame = ttk.LabelFrame(self.preview_frame, text="Original Image", padding="5")
        self.original_frame.grid(row=0, column=0, padx=5, pady=5)
        self.original_label = ttk.Label(self.original_frame)
        self.original_label.grid(row=0, column=0, padx=5, pady=5)
        
        # Stego image preview
        self.stego_frame = ttk.LabelFrame(self.preview_frame, text="Stego Image", padding="5")
        self.stego_frame.grid(row=0, column=1, padx=5, pady=5)
        self.stego_label = ttk.Label(self.stego_frame)
        self.stego_label.grid(row=0, column=0, padx=5, pady=5)
        
        # Input controls
        self.controls_frame = ttk.LabelFrame(self.main_frame, text="Controls", padding="5")
        self.controls_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Image selection
        ttk.Label(self.controls_frame, text="Cover Image:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.cover_path = tk.StringVar()
        ttk.Entry(self.controls_frame, textvariable=self.cover_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(self.controls_frame, text="Browse", command=self.browse_cover).grid(row=0, column=2)
        
        # Message input
        ttk.Label(self.controls_frame, text="Message:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.message_text = tk.Text(self.controls_frame, height=4, width=50, wrap=tk.WORD)
        self.message_text.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2)
        
        # Message buttons
        self.message_button_frame = ttk.Frame(self.controls_frame)
        self.message_button_frame.grid(row=2, column=1, columnspan=2, sticky=tk.E)
        ttk.Button(self.message_button_frame, text="Clear", command=self.clear_message).grid(row=0, column=0, padx=2)
        ttk.Button(self.message_button_frame, text="Save Message", command=self.save_message).grid(row=0, column=1, padx=2)
        
        # Password input
        ttk.Label(self.controls_frame, text="Password:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self.controls_frame, textvariable=self.password_var, show="*", width=50)
        self.password_entry.grid(row=3, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2)
        
        # Security info
        security_frame = ttk.Frame(self.controls_frame)
        security_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=2)
        ttk.Label(security_frame, text="Security: AES-256-CBC encryption with random IV", 
                 font=('Helvetica', 8, 'italic')).grid(row=0, column=0, sticky=tk.W)
        
        # Operation buttons
        self.button_frame = ttk.Frame(self.controls_frame)
        self.button_frame.grid(row=5, column=0, columnspan=3, pady=10)
        
        self.embed_button = ttk.Button(self.button_frame, text="Embed Message", command=self.embed_message)
        self.embed_button.grid(row=0, column=0, padx=5)
        self.extract_button = ttk.Button(self.button_frame, text="Extract Message", command=self.extract_message)
        self.extract_button.grid(row=0, column=1, padx=5)
        ttk.Button(self.button_frame, text="Clear All", command=self.clear_all).grid(row=0, column=2, padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.controls_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN, style='Status.TLabel')
        self.status_bar.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        self.preview_frame.columnconfigure(0, weight=1)
        self.preview_frame.columnconfigure(1, weight=1)
        
        # Add tooltips
        self.create_tooltips()
        
    def create_tooltips(self):
        self.create_tooltip(self.embed_button, "Hide your message in the selected image (AES-256-CBC encrypted)")
        self.create_tooltip(self.extract_button, "Extract and decrypt a hidden message from the stego image")
        self.create_tooltip(self.password_entry, "Enter the password used to encrypt/decrypt the message (also determines the bit plane)")
        
    def create_tooltip(self, widget, text):
        def show_tooltip(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            label = ttk.Label(tooltip, text=text, background="#ffffe0", relief="solid", borderwidth=1)
            label.pack()
            
            def hide_tooltip():
                tooltip.destroy()
            
            widget.tooltip = tooltip
            widget.bind('<Leave>', lambda e: hide_tooltip())
            
        widget.bind('<Enter>', show_tooltip)
        
    def browse_cover(self):
        filename = filedialog.askopenfilename(
            title="Select Cover Image",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        if filename:
            self.cover_path.set(filename)
            self.update_preview(filename, is_original=True)
            self.clear_stego_preview()
    
    def update_preview(self, image_path, is_original=False):
        try:
            # Load and resize image for preview
            image = Image.open(image_path)
            # Calculate resize dimensions while maintaining aspect ratio
            max_size = (300, 300)
            image.thumbnail(max_size, Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(image)
            
            if is_original:
                self.original_label.configure(image=photo)
                self.original_label.image = photo
            else:
                self.stego_label.configure(image=photo)
                self.stego_label.image = photo
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {str(e)}")
    
    def clear_stego_preview(self):
        self.stego_label.configure(image='')
        self.stego_label.image = None
    
    def clear_message(self):
        self.message_text.delete("1.0", tk.END)
    
    def clear_all(self):
        self.cover_path.set("")
        self.clear_message()
        self.password_var.set("")
        self.clear_stego_preview()
        self.original_label.configure(image='')
        self.original_label.image = None
        self.status_var.set("Ready")
        self.progress_var.set(0)
    
    def save_message(self):
        message = self.message_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Warning", "No message to save")
            return
            
        filename = filedialog.asksaveasfilename(
            title="Save Message",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(message)
                self.status_var.set(f"Message saved to: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save message: {str(e)}")
    
    def embed_message(self):
        cover_path = self.cover_path.get()
        message = self.message_text.get("1.0", tk.END).strip()
        password = self.password_var.get()
        
        if not all([cover_path, message, password]):
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        try:
            # Create output filename
            base, ext = os.path.splitext(cover_path)
            stego_path = f"{base}_stego{ext}"
            
            # Update progress
            self.progress_var.set(20)
            self.root.update()
            
            # Embed message
            embed_message_in_image(cover_path, stego_path, message, password)
            
            # Update progress
            self.progress_var.set(80)
            self.root.update()
            
            # Update preview
            self.update_preview(stego_path, is_original=False)
            self.progress_var.set(100)
            self.status_var.set(f"Message embedded successfully! Saved as: {stego_path}")
            messagebox.showinfo("Success", f"Message embedded successfully!\nSaved as: {stego_path}")
        except Exception as e:
            self.progress_var.set(0)
            messagebox.showerror("Error", f"Failed to embed message: {str(e)}")
    
    def extract_message(self):
        stego_path = self.cover_path.get()
        password = self.password_var.get()
        
        if not all([stego_path, password]):
            messagebox.showerror("Error", "Please select a stego image and enter the password")
            return
        
        try:
            # Update progress
            self.progress_var.set(20)
            self.root.update()
            
            # Extract message
            message = extract_message_from_image(stego_path, password)
            
            # Update progress
            self.progress_var.set(80)
            self.root.update()
            
            # Display message
            self.message_text.delete("1.0", tk.END)
            self.message_text.insert("1.0", message)
            self.progress_var.set(100)
            self.status_var.set("Message extracted successfully!")
        except Exception as e:
            self.progress_var.set(0)
            messagebox.showerror("Error", f"Failed to extract message: {str(e)}")

def main():
    root = tk.Tk()
    app = PhotocryptGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 