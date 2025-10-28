import random
import joblib
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
import numpy as np

# Synthetic data generation for UPI URI risk model
# Features: pa_present, pn_length, has_encoded, special_char_count, pa_numeric, pn_has_keyword, raw_length, brand_spoof_flag

PHISHING_KEYWORDS = ["login", "verify", "secure", "account", "update", "security", "alert"]


def make_sample(label):
    # label: 1 -> phishing, 0 -> legitimate
    trusted = 0
    if label == 0 and random.random() < 0.6:
        trusted = 1
    # base
    if label == 1:
        pa_present = 0 if random.random() < 0.2 else 1
    else:
        pa_present = 1 if random.random() < 0.95 else 0

    pn_len = random.randint(3, 30) if label == 0 else random.randint(0, 36)
    has_encoded = 1 if (label == 1 and random.random() < 0.4) or (label == 0 and random.random() < 0.05) else 0
    special = random.randint(0,3) if label==1 else random.randint(0,1)
    pa_numeric = 1 if random.random() < (0.4 if label==1 else 0.2) else 0
    pn_has_keyword = 1 if (label==1 and random.random() < 0.35) else 0
    raw_len = random.randint(10,200) if label==1 else random.randint(10,120)

    # Simulate explicit brand-spoof signal in phishing examples
    if label == 1:
        brand_flag = 1 if random.random() < 0.45 else 0
    else:
        brand_flag = 1 if random.random() < 0.02 else 0

    return [pa_present, pn_len, has_encoded, special, pa_numeric, pn_has_keyword, raw_len, brand_flag]


def generate_dataset(n=2000):
    X = []
    y = []
    for _ in range(n):
        # sample label distribution: 50% phishing, 50% legitimate for balanced training
        lbl = 1 if random.random() < 0.5 else 0
        X.append(make_sample(lbl))
        y.append(lbl)
    return np.array(X, dtype=float), np.array(y)


if __name__ == '__main__':
    print('Generating synthetic dataset...')
    X,y = generate_dataset(2500)
    print('Training logistic regression...')
    pipe = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', LogisticRegression(max_iter=500, class_weight='balanced'))
    ])
    pipe.fit(X,y)
    print('Saving model to upi_model.pkl')
    joblib.dump(pipe, 'upi_model.pkl')
    print('Done')
