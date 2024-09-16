import hashlib
import pyttsx3
from PIL import Image

def speak(text):
    """Use text-to-speech to speak the given text."""
    engine = pyttsx3.init()
    engine.say(text)
    engine.runAndWait()

def calculate_hash(file_path):
    """Calculate and return the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def load_image(path):
    """Load and return an image."""
    return Image.open(path)
