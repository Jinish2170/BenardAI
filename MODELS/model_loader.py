import pickle

def load_or_train_model():
    with open("models/model.pkl", "rb") as f:
        model = pickle.load(f)
    return model
