import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.impute import SimpleImputer
import warnings
warnings.filterwarnings('ignore')

def load_data(sample_size=None):
    try:
        df = pd.read_csv('majestic_million.csv')
        print(f"Total rows in dataset: {len(df):,}")
        print("Creating enhanced simulated labels...")
        df['is_phishing'] = 0
        
        risky_tlds = ['.tk', '.gq', '.ga', '.ml', '.cf', '.xyz', '.top', '.gdn', '.cc', '.pw']
        df.loc[df['TLD'].isin(risky_tlds), 'is_phishing'] = 1
        
        if 'Domain' in df.columns:
            df.loc[df['Domain'].str.len() > 30, 'is_phishing'] = 1
            df.loc[df['Domain'].str.contains(r'\d'), 'is_phishing'] = 1
        
        if 'GlobalRank' in df.columns:
            df.loc[df['GlobalRank'] > df['GlobalRank'].quantile(0.995), 'is_phishing'] = 1
        
        # Feature Engineering
        features = {}
        
        if 'Domain' in df.columns:
            features['DomainLength'] = df['Domain'].str.len()
            features['SubdomainCount'] = df['Domain'].str.count('\.')
            features['HasHyphen'] = df['Domain'].str.contains('-').astype(int)
            features['HasDigits'] = df['Domain'].str.contains(r'\d').astype(int)
        
        if 'TLD' in df.columns:
            tld_risk = {'.com':0, '.org':0, '.net':0, '.tk':1, '.gq':1, '.ga':1, '.ml':1, '.cf':1, '.cc':0.7, '.pw':0.8}
            features['TLD_Risk'] = df['TLD'].map(tld_risk).fillna(0.5)
        
        X = pd.DataFrame(features)
        y = df['is_phishing']
        
        # Preprocessing
        imp = SimpleImputer(strategy='median')
        X_imputed = imp.fit_transform(X)
        
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_imputed)
        
        # Feature selection
        k = min(10, X_scaled.shape[1])
        selector = SelectKBest(f_classif, k=k)
        X_selected = selector.fit_transform(X_scaled, y)
        
        print(f"\nSelected {k} best features")
        return X_selected, y, imp, scaler, selector
        
    except Exception as e:
        print(f"Error loading data: {e}")
        raise

def train_model():
    try:
        X, y, imp, scaler, selector = load_data(sample_size=100000)
        
        print("\n=== Dataset Statistics ===")
        print(f"Total samples loaded: {len(y):,}")
        print("\nClass distribution:")
        class_dist = y.value_counts(normalize=True)
        print(f"Legitimate: {class_dist[0]:.2%}")
        print(f"Phishing: {class_dist[1]:.2%}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print("\n=== Training/Testing Split ===")
        print(f"Training samples: {len(y_train):,} ({len(y_train)/len(y):.1%})")
        print(f"Testing samples: {len(y_test):,} ({len(y_test)/len(y):.1%})")
        print(f"Training phishing samples: {y_train.sum():,}")
        print(f"Testing phishing samples: {y_test.sum():,}")
        
        params = {
            'n_estimators': [100, 150],
            'learning_rate': [0.1, 0.2],
            'max_depth': [3, 4],
            'subsample': [0.8]
        }
        
        print("\nTraining model with GridSearchCV...")
        model = GridSearchCV(
            GradientBoostingClassifier(random_state=42),
            params,
            cv=3,
            scoring='f1',
            n_jobs=-1,
            verbose=1
        )
        model.fit(X_train, y_train)
        
        # Evaluation
        y_pred = model.predict(X_test)
        print("\n=== Model Evaluation ===")
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.2%}")
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        print("\nBest Parameters:", model.best_params_)
        
        # Save everything needed for prediction
        joblib.dump({
            'model': model.best_estimator_,
            'imputer': imp,
            'scaler': scaler,
            'selector': selector,
            'feature_names': ['DomainLength', 'SubdomainCount', 'HasHyphen', 'HasDigits', 'TLD_Risk'],
            'training_stats': {
                'total_samples': len(y),
                'train_samples': len(y_train),
                'test_samples': len(y_test),
                'phishing_ratio': class_dist[1],
                'train_phishing': y_train.sum(),
                'test_phishing': y_test.sum()
            }
        }, 'classifier.pkl')
        
        print("\nModel and preprocessing pipeline saved successfully!")
        
    except Exception as e:
        print(f"Error in training: {e}")

if __name__ == "__main__":
    train_model()