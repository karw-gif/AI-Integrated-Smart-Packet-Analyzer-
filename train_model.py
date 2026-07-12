"""
Retrains the NIDS models from the UNSW-NB15 dataset using the currently
installed library versions, eliminating pickle version-skew issues.

Produces:
  - xgboost_network_model.json   (binary attack/normal classifier, native XGBoost format)
  - xgboost_attack_model.json    (multi-class attack-category classifier)
  - label_encoders.pkl           (categorical encoders, regenerated)
  - feature_columns.pkl          (exact feature order fed to the models)
  - attack_classes.pkl           (attack category names for the multi-class model)
  - model_metrics.pkl            (held-out evaluation metrics for the dashboard)

Run:  py train_model.py
"""
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix,
                             classification_report)
from xgboost import XGBClassifier

# The file named "testing" actually holds the official 175k TRAINING split and
# vice versa (this mix-up shipped with the original project). We train on the
# large split and evaluate on the 82k split the model never sees.
TRAIN_CSV = 'data/NB_testing-set.csv'   # 175,341 rows -> training
TEST_CSV = 'data/NB_training-set.csv'   # 82,332 rows  -> held-out evaluation

CATEGORICAL = ['proto', 'service', 'state']
DROP_COLS = ['id', 'attack_cat', 'label']

# UNSW-NB15 "artifact" features: near-perfect separators inside the dataset
# (fixed simulation TTLs, constant window sizes, raw TCP sequence numbers)
# that do not generalize to real captured traffic and cause the model to
# flag benign live flows as attacks.
# tcprtt/synack/ackdat are also artifacts: normal traffic was generated on a
# ~0.1ms LAN while attack traffic came through ~60ms paths, so handshake
# latency encodes lab topology, not attack behavior — real internet flows
# (20-100ms RTT) would all look "attack-like".
ARTIFACT_FEATURES = ['sttl', 'dttl', 'ct_state_ttl', 'swin', 'dwin', 'stcpb', 'dtcpb',
                     'tcprtt', 'synack', 'ackdat']


def load_data():
    train = pd.read_csv(TRAIN_CSV)
    test = pd.read_csv(TEST_CSV)
    return train, test


def encode(train, test):
    encoders = {}
    for col in CATEGORICAL:
        le = LabelEncoder()
        train[col] = train[col].astype(str).str.lower()
        test[col] = test[col].astype(str).str.lower()
        le.fit(pd.concat([train[col], test[col]]).unique())
        train[col] = le.transform(train[col])
        test[col] = le.transform(test[col])
        encoders[col] = le
    return encoders


def eval_binary(model, X, y):
    prob = model.predict_proba(X)[:, 1]
    pred = (prob >= 0.5).astype(int)
    return {
        'accuracy': accuracy_score(y, pred),
        'precision': precision_score(y, pred),
        'recall': recall_score(y, pred),
        'f1': f1_score(y, pred),
        'roc_auc': roc_auc_score(y, prob),
        'confusion_matrix': confusion_matrix(y, pred).tolist(),
    }


def main():
    print('Loading data...')
    train, test = load_data()
    encoders = encode(train, test)

    all_features = [c for c in train.columns if c not in DROP_COLS]
    robust_features = [c for c in all_features if c not in ARTIFACT_FEATURES]

    results = {}
    for name, feats in [('all-42-features', all_features),
                        ('robust-features', robust_features)]:
        model = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.15,
                              tree_method='hist', eval_metric='logloss',
                              n_jobs=-1, random_state=42)
        model.fit(train[feats], train['label'])
        metrics = eval_binary(model, test[feats], test['label'])
        results[name] = (model, feats, metrics)
        print(f"\n[{name}] ({len(feats)} features)")
        for k, v in metrics.items():
            if k != 'confusion_matrix':
                print(f"  {k}: {v:.4f}")
        print(f"  confusion_matrix: {metrics['confusion_matrix']}")

    # The robust variant is the one we ship: slightly lower benchmark score but
    # dramatically better behavior on live traffic. Keep both scores for the report.
    model, features, metrics = results['robust-features']
    metrics_all = results['all-42-features'][2]

    print('\nTraining multi-class attack-category model (robust features)...')
    cat_le = LabelEncoder()
    y_cat_train = cat_le.fit_transform(train['attack_cat'])
    y_cat_test = cat_le.transform(test['attack_cat'])
    attack_model = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.15,
                                 tree_method='hist', eval_metric='mlogloss',
                                 n_jobs=-1, random_state=42)
    attack_model.fit(train[features], y_cat_train)
    cat_pred = attack_model.predict(test[features])
    cat_acc = accuracy_score(y_cat_test, cat_pred)
    cat_report = classification_report(y_cat_test, cat_pred,
                                       target_names=cat_le.classes_,
                                       output_dict=True, zero_division=0)
    print(f'  attack-category accuracy: {cat_acc:.4f}')

    importances = sorted(zip(features, model.feature_importances_.tolist()),
                         key=lambda t: -t[1])

    print('\nSaving artifacts...')
    model.save_model('xgboost_network_model.json')
    attack_model.save_model('xgboost_attack_model.json')
    joblib.dump(encoders, 'label_encoders.pkl')
    joblib.dump(features, 'feature_columns.pkl')
    joblib.dump(list(cat_le.classes_), 'attack_classes.pkl')
    joblib.dump({
        'binary': metrics,
        'binary_all_features': metrics_all,
        'attack_cat_accuracy': cat_acc,
        'attack_cat_report': cat_report,
        'feature_importances': importances,
        'n_train': len(train), 'n_test': len(test),
        'features': features,
        'dropped_artifact_features': ARTIFACT_FEATURES,
    }, 'model_metrics.pkl')
    print('Done. Artifacts written.')


if __name__ == '__main__':
    main()
