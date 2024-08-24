import tkinter as tk
from tkinter import ttk, filedialog
import customtkinter
from PIL import Image, ImageTk
import threading
import logging

from scripts.utils import init_logging, text_to_speech
from scripts.file_scanner import FileScanner
from scripts.model import ModelManager

# Configure logging
init_logging()

class DariusAI(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # Configure window
        self.title("DariusAI - Cybersecurity Assistant")
        self.geometry("1000x650")

        # Set custom theme colors
        customtkinter.set_appearance_mode("Dark")
        customtkinter.set_default_color_theme("blue")

        # Load background image
        self.background_image = Image.open("data/iron_man_interface.jpg")
        self.background_photo = ImageTk.PhotoImage(self.background_image)
        self.background_label = tk.Label(self, image=self.background_photo)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        # Create frames
        self.main_frame = customtkinter.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True)

        self.conversation_frame = customtkinter.CTkScrollableFrame(self.main_frame, fg_color="transparent")
        self.conversation_frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.input_frame = customtkinter.CTkFrame(self.main_frame, fg_color="transparent")
        self.input_frame.pack(pady=20, padx=20, fill="x")

        # Conversation text
        self.conversation_text = customtkinter.CTkTextbox(self.conversation_frame, state="normal", width=600, height=300, fg_color="transparent", text_color="white")
        self.conversation_text.pack(pady=10, padx=10, fill="both", expand=True)
        self.conversation_text.configure(state="disabled")

        # Input elements
        self.input_entry = customtkinter.CTkEntry(self.input_frame, placeholder_text="Type your query...", width=600, text_color="white")
        self.input_entry.pack(side="left", padx=10)
        self.input_entry.bind("<Return>", self.process_input)

        # Buttons
        self.buttons = {
            "speak": {"text": "Speak", "command": self.listen, "side": "left", "padx": 10},
            "submit": {"text": "Submit", "command": self.process_input, "side": "right", "padx": 10},
            "scan": {"text": "Scan File", "command": self.browse_file, "side": "right", "padx": 10}
        }
        for button in self.buttons.values():
            btn = customtkinter.CTkButton(self.input_frame, text=button["text"], command=button["command"], fg_color="transparent", hover_color="#4CAF50", text_color="white")
            btn.pack(side=button["side"], padx=button["padx"])

        # Initialize text-to-speech engine
        self.engine = text_to_speech()
        self.model_manager = ModelManager()
        self.file_scanner = FileScanner(self.model_manager)

        # Welcome message
        self.insert_text("DariusAI: Hello! I'm DariusAI, your cybersecurity assistant.\n"
                         "I can help you scan files for potential malware threats and perform various Windows operations. You can type or speak your queries.\n", "greeting")
        self.speak("Hello! I'm DariusAI, your cybersecurity assistant. How can I help you today?")

        # Placeholder for model accuracy display (update hourly)
        self.model_accuracy_label = customtkinter.CTkLabel(self.main_frame, text="Model Accuracy: N/A", fg_color="transparent", text_color="white")
        self.model_accuracy_label.pack(pady=10)
        self.update_model_accuracy()

    def insert_text(self, text, tag="default"):
        self.conversation_text.configure(state="normal")
        self.conversation_text.insert("end", text, tag)
        self.conversation_text.see("end")
        self.conversation_text.configure(state="disabled")

    def speak(self, text):
        self.engine.say(text)
        self.engine.runAndWait()

    def process_input(self, event=None):
        user_input = self.input_entry.get()
        self.insert_text(f"You: {user_input}\n", "user")
        self.input_entry.delete(0, "end")

        self.process_command(user_input)

    def process_command(self, command):
        command = command.lower()

        if "scan file" in command:
            self.browse_file()
        elif "clear" in command:
            self.conversation_text.configure(state="normal")
            self.conversation_text.delete("1.0", "end")
            self.conversation_text.configure(state="disabled")
            self.insert_text("DariusAI: Conversation cleared.\n", "info")
            self.speak("Conversation cleared.")
        elif "exit" in command:
            self.speak("Goodbye!")
            self.destroy()
        elif "open" in command:
            app = command.split("open ")[-1]
            self.open_application(app)
        elif "close" in command:
            app = command.split("close ")[-1]
            self.close_application(app)
        elif "volume" in command:
            if "up" in command:
                self.adjust_volume(1)
            elif "down" in command:
                self.adjust_volume(-1)
            elif "mute" in command:
                self.mute_volume()
        elif "brightness" in command:
            if "up" in command:
                self.adjust_brightness(10)
            elif "down" in command:
                self.adjust_brightness(-10)
        elif "wifi" in command:
            if "on" in command:
                self.toggle_wifi(True)
            elif "off" in command:
                self.toggle_wifi(False)
        elif "bluetooth" in command:
            if "on" in command:
                self.toggle_bluetooth(True)
            elif "off" in command:
                self.toggle_bluetooth(False)
        elif "train model" in command:
            threading.Thread(target=self.model_manager.train_model).start()
            self.insert_text("DariusAI: Training the model. This will take a few minutes.\n", "info")
            self.speak("Training the model. This will take a few minutes.")
        elif "what can you do" in command:
            self.show_capabilities()
        else:
            self.insert_text("DariusAI: I'm not sure I understand. Can you please rephrase your request?\n", "error")
            self.speak("I'm not sure I understand. Can you please rephrase your request?")

    def listen(self):
        recognizer = sr.Recognizer()
        with sr.Microphone() as source:
            self.insert_text("DariusAI: Listening...\n", "info")
            self.speak("I'm listening.")
            audio = recognizer.listen(source)
        try:
            self.insert_text("DariusAI: Recognizing...\n", "info")
            text = recognizer.recognize_google(audio)
            self.insert_text(f"You: {text}\n", "user")
            self.process_command(text)
        except sr.UnknownValueError:
            self.insert_text("DariusAI: I didn't catch that. Could you please repeat?\n", "error")
            self.speak("I didn't catch that. Could you please repeat?")
        except sr.RequestError:
            self.insert_text("DariusAI: There was an error with the speech recognition service. Please try again later.\n", "error")
            self.speak("There was an error with the speech recognition service. Please try again later.")

    def update_model_accuracy(self):
        accuracy = self.model_manager.get_accuracy()
        self.model_accuracy_label.configure(text=f"Model Accuracy: {accuracy:.2f}")
        self.after(3600000, self.update_model_accuracy)  # Update every hour

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_scanner.scan_file(file_path)

    # Add methods for open_application, close_application, adjust_volume, mute_volume, adjust_brightness, toggle_wifi, toggle_bluetooth, and show_capabilities

