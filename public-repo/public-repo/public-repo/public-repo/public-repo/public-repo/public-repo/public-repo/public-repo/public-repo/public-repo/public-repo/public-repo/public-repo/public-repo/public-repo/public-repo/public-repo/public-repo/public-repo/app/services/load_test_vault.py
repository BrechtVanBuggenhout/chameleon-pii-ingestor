import asyncio
import aiohttp
import time
import uuid

VAULT_URL = "http://localhost:8080"
TENANT_ID = "stress-test-tenant"
CONCURRENCY = 100
TOTAL_REQUESTS = 1000

async def call_encryption_context(session, user_id):
    url = f"{VAULT_URL}/key/{user_id}/encryption-context"
    headers = {"X-Tenant-Id": TENANT_ID}
    try:
        start = time.perf_counter()
        async with session.get(url, headers=headers) as resp:
            status = resp.status
            await resp.json()
            duration = time.perf_counter() - start
            return status, duration
    except Exception as e:
        return str(e), 0

async def main():
    print(f"🚀 Starting Vault Load Test: {TOTAL_REQUESTS} requests, {CONCURRENCY} concurrency")
    async with aiohttp.ClientSession() as session:
        tasks = []
        # Pre-generate IDs
        uids = [f"load_user_{uuid.uuid4().hex[:8]}" for _ in range(TOTAL_REQUESTS)]
        
        start_time = time.perf_counter()
        
        # Simple semaphore to control concurrency
        sem = asyncio.Semaphore(CONCURRENCY)

        async def sem_task(uid):
            async with sem:
                return await call_encryption_context(session, uid)

        results = await asyncio.gather(*(sem_task(u) for u in uids))
        
        total_duration = time.perf_counter() - start_time
        
        statuses = [r[0] for r in results]
        latencies = [r[1] for r in results if isinstance(r[0], int)]
        
        print(f"\n--- Load Test Results ---")
        print(f"Total Time: {total_duration:.2f}s")
        print(f"Requests Per Second: {TOTAL_REQUESTS/total_duration:.2f}")
        print(f"Success (200): {statuses.count(200)}")
        print(f"Avg Latency: {sum(latencies)/len(latencies)*1000:.2f}ms" if latencies else "N/A")

if __name__ == "__main__":
    asyncio.run(main())