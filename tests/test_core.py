import os
import pandas as pd
from mock_data import build_network_telemetry
from engine import process_and_inspect_logs
from config import DATA_LOG_SOURCE

def test_siem_integrity():
    build_network_telemetry(10)
    assert os.path.exists(DATA_LOG_SOURCE)

    df, err = process_and_inspect_logs(DATA_LOG_SOURCE)
    assert err is None
    assert 'Severity' in df.columns
