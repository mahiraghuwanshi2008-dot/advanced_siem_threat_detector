import pandas as pd
from sklearn.ensemble import IsolationForest
from config import MAX_FAILED_ATTEMPTS, DETECTION_CONTAMINATION_RATE

def process_and_inspect_logs(filepath):
    try:
        metrics_df = pd.read_csv(filepath)
    except FileNotFoundError:
        return None, "Target log repository missing."
        
    failed_sessions = metrics_df[metrics_df['Session_Status'] == 'Failed']
    attack_frequency = failed_sessions['Origin_IP'].value_counts()
    malicious_ips = attack_frequency[attack_frequency > MAX_FAILED_ATTEMPTS].index.tolist()
    
    metrics_df['Severity'] = 'Low'
    metrics_df['Incident_Classification'] = 'Standard Operations'
    
    brute_force_condition = metrics_df['Origin_IP'].isin(malicious_ips) & (metrics_df['Session_Status'] == 'Failed')
    metrics_df.loc[brute_force_condition, 'Severity'] = 'High'
    metrics_df.loc[brute_force_condition, 'Incident_Classification'] = 'Brute Force Intrusion Attempt'
    
    encoding_matrix = pd.get_dummies(metrics_df[['Session_Status', 'Network_Protocol']], drop_first=True)
    
    isolation_model = IsolationForest(contamination=DETECTION_CONTAMINATION_RATE, random_state=101)
    metrics_df['Structural_Anomaly_Score'] = isolation_model.fit_predict(encoding_matrix)
    
    anomaly_condition = metrics_df['Structural_Anomaly_Score'] == -1
    metrics_df.loc[anomaly_condition & (metrics_df['Severity'] != 'High'), 'Severity'] = 'Medium'
    metrics_df.loc[anomaly_condition & (metrics_df['Incident_Classification'] == 'Standard Operations'), 'Incident_Classification'] = 'Anomalous Behavioral Pattern'
    
    return metrics_df, None