import os
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.datasets import fetch_20newsgroups
from sklearn.feature_extraction.text import TfidfVectorizer
import logging

def load_or_train_model():
    """Load a pre-trained model from disk or train a new one if not available."""
    try:
        if os.path.exists("model.pkl"):
            with open("model.pkl", "rb") as f:
                data = pickle.load(f)
                vectorizer, model = data["vectorizer"], data["classifier"]
                logging.info("Model loaded successfully.")
        else:
            vectorizer, model = train_model()
        return model, vectorizer
    except Exception as e:
        logging.error(f"Failed to load model: {e}")
        raise

def train_model():
    """Train a new RandomForest model."""
    logging.info("Training model...")
    
    # Fetching datasets
    data_20ng = fetch_20newsgroups(subset="all")
    vectorizer = TfidfVectorizer(stop_words="english", max_features=20000)
    features = vectorizer.fit_transform(data_20ng.data)
    labels = data_20ng.target

    # Hyperparameter tuning
    param_grid = {'n_estimators': [100, 200], 'max_depth': [None, 20, 30]}
    rf = RandomForestClassifier(random_state=42)
    model = GridSearchCV(rf, param_grid, cv=5, n_jobs=-1)
    model.fit(features, labels)

    # Saving model
    with open("model.pkl", "wb") as f:
        pickle.dump({"vectorizer": vectorizer, "classifier": model}, f)
    
    logging.info("Model training completed.")
    return vectorizer, model
