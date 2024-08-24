import os
import pickle
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.datasets import fetch_20newsgroups
from sklearn.feature_extraction.text import TfidfVectorizer

class ModelManager:
    def __init__(self):
        self.model = None
        self.tfidf_vectorizer = None
        self.load_model()

    def load_model(self):
        if os.path.exists("models/model.pkl"):
            try:
                with open("models/model.pkl", "rb") as f:
                    data = pickle.load(f)
                    self.tfidf_vectorizer = data["vectorizer"]
                    self.model = data["classifier"]
                logging.info("Model loaded successfully.")
            except Exception as e:
                logging.error(f"Error loading model: {e}")
                self.train_model()
        else:
            self.train_model()

    def train_model(self):
        try:
            logging.info("Training model, please wait...")
            data = fetch_20newsgroups(subset="all")
            self.tfidf_vectorizer = TfidfVectorizer(stop_words="english", max_features=10000)
            features = self.tfidf_vectorizer.fit_transform(data.data)
            labels = data.target

            param_grid = {'n_estimators': [50, 100, 200], 'max_depth': [None, 10, 20, 30]}
            rf = RandomForestClassifier(random_state=42)
            self.model = GridSearchCV(rf, param_grid, cv=5, n_jobs=-1)
            self.model.fit(features, labels)

            with open("models/model.pkl", "wb") as f:
                pickle.dump({"vectorizer": self.tfidf_vectorizer, "classifier": self.model}, f)

            logging.info("Model training completed.")
        except Exception as e:
            logging.error(f"Error training model: {e}")

    def vectorize_text(self, text):
        return self.tfidf_vectorizer.transform([text])

    def predict(self, features):
        return self.model.predict(features)

    def get_accuracy(self):
        data = fetch_20newsgroups(subset="test")
        features = self.tfidf_vectorizer.transform(data.data)
        labels = data.target
        return self.model.score(features, labels)
