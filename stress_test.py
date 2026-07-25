import os
import pandas as pd
import time
import requests
import uuid
import logging
from concurrent.futures import ThreadPoolExecutor
from app.config import settings
from app.services.vault_client import VaultClient
from app.services.bigquery_client import BigQueryService
from app.pipelines.ingestion import IngestionPipeline

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("StressTest")

VAULT_URL = "http://localhost:8080"
JANITOR_URL = "http://localhost:8000"
TENANT_ID = "stress-test-tenant"
NUM_USERS =   100 # Adjustable to 10k for full stress testing

def generate_test_data(filename, count):
    logger.info(f"Generating {count} test records...")
    data = {
        "user_id": [f"user_{i}_{uuid.uuid4().hex[:8]}" for i in range(count)],
        "email": [f"user_{i}@example.com" for i in range(count)]
    }
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    return df['user_id'].tolist()

def run_stress_test():
    # 1. Initialization
    # Ensure the Vault (port 8080) and Janitor (port 8000) are running
    vault = VaultClient(base_url=VAULT_URL, tenant_id=TENANT_ID)
    operation_id = str(uuid.uuid4())
    # Using the explicit topic path confirmed by the Infra team
    topic_id = "projects/your-gcp-project-id/topics/pii-ingestion-stream-dev"
    lineage_topic_id = "projects/your-gcp-project-id/topics/pii-lineage-events-stream-dev"
    
    pipeline = IngestionPipeline(vault=vault, topic_id=topic_id, lineage_topic_id=lineage_topic_id)
    
    test_file = "stress_test_data.csv"
    user_ids = generate_test_data(test_file, NUM_USERS)

    # 1.5. Key Generation Phase
    # Ensure keys exist in Vault before ingestion begins
    logger.info(f"🔑 Generating keys for {NUM_USERS} users in Vault...")
    try:
        vault.batch_create_keys(user_ids)
        success_count = NUM_USERS
    except Exception as e:
        logger.error(f"Failed to batch-create keys: {e}")
        success_count = 0
    logger.info(f"✨ Key generation complete. Success: {success_count}/{NUM_USERS}")
    
    if success_count < NUM_USERS:
        logger.error("🛑 Aborting stress test: Not all keys were successfully created in the Vault.")
        return
    
    # 1.6. Cooldown Phase
    # Allow a moment for the Vault/Firestore to commit changes before mass ingestion starts
    time.sleep(5)
    
    # 2. Ingestion Phase
    logger.info("🚀 Starting Ingestion Phase...")
    start_time = time.time()
    try:
        pipeline.process_file(test_file, operation_id=operation_id)
        ingestion_duration = time.time() - start_time
        logger.info(f"✅ Ingested {NUM_USERS} records in {ingestion_duration:.2f} seconds.")
    except Exception as e:
        logger.error(f"❌ Ingestion failed: {e}")
        return

    # 2.5. Async Verification Phase
    # Give Pub/Sub -> BigQuery subscription a few seconds to flush the buffer
    logger.info("⏳ Waiting 10s for Pub/Sub to BigQuery delivery...")
    time.sleep(10)
    
    # NOTE: In a real test, you'd use the BigQueryService here to verify 
    # SELECT count(*) FROM stg_users WHERE operation_id = ...

    # 3. Shredding Phase (Sample 50 users for shredding)
    shred_sample = user_ids[:50]
    logger.info(f"🔥 Triggering shredding for {len(shred_sample)} users via Janitor...")

    # Ensure the Janitor is responsive before bombarding it
    try:
        health_resp = requests.get(f"{JANITOR_URL}/health", timeout=5)
        health_resp.raise_for_status()
        logger.info("💚 Janitor is healthy. Proceeding with shredding phase.")
    except Exception as e:
        logger.error(f"🛑 Janitor health check failed: {e}. Is the service running on port 8000?")
        return

    # Use a session to reuse connections for efficiency
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    def trigger_shred(uid, session):
        try:
            # Hitting the Vault directly (8080) via DELETE as per API Spec
            resp = session.delete(
                f"{VAULT_URL}/key/shred",
                json={"userId": uid, "tenantId": TENANT_ID},
                headers={"X-Tenant-Id": TENANT_ID},
                timeout=30
            )
            return resp.status_code
        except Exception as e:
            return str(e)

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(lambda uid: trigger_shred(uid, session), shred_sample))
    
    logger.info(f"📊 Shred Request Results (StatusCodes): {set(results)}")

    # 3.5. Certificate Verification Phase
    # Shredding is async in the Janitor. Wait for the "Certificate of Destruction" to be issued.
    logger.info("📜 Verifying Certificates of Destruction (JWTs) in Vault...")
    time.sleep(5) # Give the Janitor/Vault a moment to finalize the CoD
    
    certs_found = 0
    for uid in shred_sample:
        try:
            cert = vault.get_shred_certificate(uid)
            if cert:
                certs_found += 1
                logger.debug(f"✅ Certificate found for {uid}")
        except Exception as e:
            logger.warning(f"⚠️ Could not retrieve certificate for {uid}: {e}")

    logger.info(f"🏆 Verification Complete: Found {certs_found}/{len(shred_sample)} Certificates of Destruction.")

    # 4. Cleanup and Flush
    logger.info("📡 Flushing background lineage events...")
    vault.shutdown()

    if os.path.exists(test_file):
        os.remove(test_file)

if __name__ == "__main__":
    run_stress_test()
