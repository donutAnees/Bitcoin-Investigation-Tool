import pickle

with open("./aiml/models/wallets_dataset/RF.pkl") as f:
    model = pickle.load(f)

def results(walletid):
    X = []
    y = model.predict()