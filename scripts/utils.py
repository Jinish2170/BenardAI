import pyttsx3
import logging

def init_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def text_to_speech():
    engine = pyttsx3.init()
    engine.setProperty('voice', 'english-us')
    return engine
