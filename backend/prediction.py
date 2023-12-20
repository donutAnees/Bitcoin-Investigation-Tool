import joblib
import pandas as pd
import get_wallet_features

model = joblib.load("../aiml/model/wallets_dataset/RFModel_Wallets.pkl")

def results(walletid):
    X = ['first_sent_block','fees_max','first_block_appeared_in','fees_median','fees_mean','last_block_appeared_in','blocks_btwn_txs_max','blocks_btwn_output_txs_max','blocks_btwn_output_txs_mean']
    feature_values = get_wallet_features.get_wallet_feat(walletid)
    input_features = pd.DataFrame([feature_values],columns = X)
    print(input_features)
    y = model.predict(input_features)[0]
    if y == 1:
        prediction = "illegal"
    else:
        prediction = "legal"
    return prediction
    
# print(results("1121MFrce2rKw5XRuG7mWCSesLxRrx6Q5A"))
print(results("14z8PbPKmJMdGPRSVr2u7hHhFemThCK3Rk"))
