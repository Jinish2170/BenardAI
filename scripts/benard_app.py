import tkinter as tk
from tkinter import filedialog
import customtkinter as ctk
import threading
from utils import speak, load_image
from MODELS.model import load_or_train_model
from file_scanner import scan_file
from network_scanner import run_network_scan

class BenardApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configure window
        self.title("BenardAI - Cybersecurity Assistant")
        self.geometry("1000x650")

        # Set Appearance
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        # Main Frame
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True)

        # Conversation Frame
        self.conversation_frame = ctk.CTkScrollableFrame(self.main_frame, fg_color="transparent")
        self.conversation_frame.pack(pady=20, padx=20, fill="both", expand=True)

        # Input Frame
        self.input_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.input_frame.pack(pady=20, padx=20, fill="x")

        # Conversation Textbox
        self.conversation_text = ctk.CTkTextbox(self.conversation_frame, state="normal", width=600, height=300, fg_color="transparent", text_color="white")
        self.conversation_text.pack(pady=10, padx=10, fill="both", expand=True)
        self.conversation_text.configure(state="disabled")

        # Input Entry
        self.input_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Type your query...", width=600, text_color="white")
        self.input_entry.pack(side="left", padx=10)
        self.input_entry.bind("<Return>", self.process_input)

        # Buttons
        buttons = [("Speak", self.listen), ("Select", self.browse_file), ("Submit", self.process_input), ("Network Scan", self.network_scan)]
        for btn_text, command in buttons:
            btn = ctk.CTkButton(self.input_frame, text=btn_text, command=command, fg_color="transparent", hover_color="#4CAF50", text_color="white")
            btn.pack(side="right", padx=10)

        # Debugging info while loading model
        self.insert_text("BenardAI: Loading model...\n", "info")

        # Load Model in the Background
        threading.Thread(target=self.load_model).start()

    def load_model(self):
        """Load the model in the background to avoid freezing the UI."""
        try:
            self.model, self.vectorizer = load_or_train_model()
            self.insert_text("BenardAI: Model loaded successfully!\n", "success")
            speak("Model loaded successfully.")
        except Exception as e:
            self.insert_text(f"Error loading model: {e}\n", "error")

    def insert_text(self, text, tag="default"):
        """Insert text into the conversation frame."""
        self.conversation_text.configure(state="normal")
        self.conversation_text.insert("end", text, tag)
        self.conversation_text.see("end")
        self.conversation_text.configure(state="disabled")

    def process_input(self, event=None):
        """Process user input from the entry box."""
        user_input = self.input_entry.get()
        if user_input:
            self.insert_text(f"You: {user_input}\n")
            self.input_entry.delete(0, tk.END)
            # Handle user input here (e.g., call a bot function)

    def browse_file(self):
        """Open file dialog to browse and scan a file."""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.insert_text(f"You selected: {file_path}\n")
            self.insert_text("BenardAI: Scanning file...\n", "info")
            threading.Thread(target=self.scan_file, args=(file_path,)).start()

    def scan_file(self, file_path):
        """Scan the selected file."""
        try:
            scan_file(file_path, self.model, self.vectorizer, self)
        except Exception as e:
            self.insert_text(f"Error: {e}\n", "error")

    def listen(self):
        """Handle voice input."""
        # Implement voice input handling here
        pass

    def network_scan(self):
        """Handle network scanning."""
        self.insert_text("BenardAI: Starting network scan...\n", "info")
        threading.Thread(target=run_network_scan, args=(self,)).start()
