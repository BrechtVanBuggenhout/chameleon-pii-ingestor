import os
import pandas as pd
from unittest.mock import MagicMock
from app.pipelines.ingestion import IngestionPipeline

def run_test_ingestion():
    print("🚀 Starting Ingestion Pipeline Test Harness...")
    
    # 1. Setup Mock Services
    mock_vault = MagicMock()
    mock_bq = MagicMock()
    mock_bq.dataset_id = "chameleon_test"
    
    # Mock a fixed context for all users in this test
    mock_vault.get_encryption_context.return_value = {
        "dek": "a" * 64,
        "encryption_version": "v2",
        "status": "ACTIVE"
    }
    
    pipeline = IngestionPipeline(vault=mock_vault, bq_service=mock_bq)
    
    # 2. Create dummy data
    test_file = "test_signups.csv"
    data = {
        "userId": ["user_1", "user_2"],
        "email": ["alice@example.com", "bob@example.com"]
    }
    pd.DataFrame(data).to_csv(test_file, index=False)
    
    try:
        # 3. Run Pipeline
        print(f"📦 Processing {test_file}...")
        pipeline.process_file(test_file)
        
        # 4. Verify Results
        print("✅ Lineage reported to Vault.")
        assert mock_vault.report_lineage.called
        
        print("✅ Data pushed to BigQuery service.")
        assert mock_bq.load_records.called
        
        # Check that the data was actually transformed
        args, _ = mock_bq.load_records.call_args
        records = args[1]
        assert "email_ciphertext" in records[0]
        assert records[0]["email_ciphertext"] != "alice@example.com"

        print("\n✨ TEST SUCCESSFUL: Pipeline correctly transformed and routed data.")
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)

if __name__ == "__main__":
    run_test_ingestion()