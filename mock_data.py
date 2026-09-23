import pandas as pd
import random
from datetime import datetime, timedelta
from config import DATA_LOG_SOURCE

def build_network_telemetry(records_count=250):
    source_ips = ["192.168.1.45", "10.0.0.12", "172.16.5.99", "198.51.100.4", "203.0.113.8"]
    target_users = ["admin", "root", "sys_ops", "user_test", "service_account"]
    auth_outcomes = ["Success", "Failed"]
    protocols = ["SSH", "RDP", "HTTPS", "FTP"]
    
    telemetry_records = []
    start_time = datetime.now() - timedelta(days=1)
    
    for idx in range(records_count):
        if 180 < idx < 205:
            ip = "198.51.100.4"
            identity = "admin"
            outcome = "Failed"
            proto = "SSH"
            timestamp = start_time + timedelta(seconds=idx * 2)
        else:
            ip = random.choice(source_ips)
            identity = random.choice(target_users)
            outcome = random.choices(auth_outcomes, weights=[0.85, 0.15])[0]
            proto = random.choice(protocols)
            timestamp = start_time + timedelta(minutes=idx * 5)
            
        telemetry_records.append({
            "Timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "Origin_IP": ip,
            "Target_User": identity,
            "Session_Status": outcome,
            "Network_Protocol": proto
        })
        
    dataset = pd.DataFrame(telemetry_records)
    dataset.to_csv(DATA_LOG_SOURCE, index=False)