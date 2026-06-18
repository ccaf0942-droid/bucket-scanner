import os 
import boto3
from botocore.exceptions import ClientError
import requests
import json
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from requests.exceptions import ConnectionError, Timeout
from botocore.config import Config
from typing import Any
import logging
import psycopg2
from psycopg2.extras import Json

def all_pages(url: str, params: dict[str, str], key: str | None = None) -> list[dict[list, Any]]:
    items = []
    hut = None
    
    while True:
        if hut:
            params["pageToken"] = hut
        data = yc_get(url, params)
        items += data.get(ket, [])
        
        hut = data.get("nextPageToken")
        
        if not hut:
            break
    return items

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
load_dotenv()

token = os.getenv("TOKEN")
folder_id = os.getenv("FOLDER_ID")
key = os.getenv("key_id")
secret_key = os.getenv("secret_key")

config = Config(
    retries={
        "max_attempts": 3,
        "mode": "adaptive"
    }
)

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1,max=10),
    retry=retry_if_exception_type((ConnectionError, Timeout))
)
def yc_get(url: str, params: dict[str, str] | None = None) -> dict[str, Any]: 
    logger.info(f"Запрос к api: {url}")
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, params=params, timeout=30)

    if response.status_code != 200:
        logger.error(f"ERROR: {response.status_code}")
        return {}
    return response.json()

def get_all_pages(url: str, params: dict[str, str], key: str) -> list[dict[str, Any]]:
    items = []
    tok = None
    
    while True:
        if tok:
            params["pageToken"] = tok
        data = yc_get(url, params)    
        items += data.get(key, [])
        
        tok = data.get("nextPageToken")
        if not tok:
            break
    return items

    
def bucket_get(folder_id: str) -> list[dict[str, Any]]:
    url = "https://storage.api.cloud.yandex.net/storage/v1/buckets"
    return get_all_pages(url, {"folderId": folder_id}, "buckets")

def boto3_logging():
    client = boto3.client(
        's3',
        endpoint_url='https://storage.yandexcloud.net',
        aws_access_key_id=key,
        aws_secret_access_key=secret_key,
        region_name='ru-central1',
        config=config
    )
    return client

def bucket_policy(client: Any, name: str) -> str | dict[str, Any]:
    try:
        response = client.get_bucket_policy(Bucket=name)
        jsons = json.loads(response['Policy'])
        state = jsons.get("Statement", [])

        flags = False

        for i in state:
            effect = i.get("Effect", "")
            pris = i.get("Principal", "")

            if effect == "Allow" and (pris == "*" or pris == {"AWS": "*"}):
                flags = True
                break
        if flags:
            logger.warning(f"Бакет: {name}: Policy - DANGER")
            return "DANGER"
        logger.info(f"Бакет: {name}: Policy - SAFE")
        return "SAFE"
    except ClientError as e: 
        if e.response['Error']['Code'] == "NoSuchBucketPolicy":
            logger.warning(f"Бакет: {name}: Policy - NO_CONFIGURATION")
            return "NO_CONFIGURATION"
        else:
            logger.error(f"Бакет: {name}: Policy - ERROR: {e}")
            return {"ERROR": e}

def bucket_versioning(client: Any, name: str) -> str | dict[str, Any]:
    try:
        response = client.get_bucket_versioning(Bucket=name)
        status = response.get("Status", "Suspended")
        logger.info(f"Бакет: {name}: Versioning - status: {status}")
        return {"Status": status}
    except ClientError as e:
        logger.error(f"Бакет: {name}: Versioning - ERROR: {e}")
        return {"Error": e}

def bucket_encrriptyon(client: Any, name: str) -> str | dict[str, Any]:
    try:
        response = client.get_bucket_encryption(Bucket=name)
        logger.info(f"Бакет: {name}: Encryption - {response}")
        return response
    except ClientError as e:
        if e.response['Error']['Code'] == "ServerSideEncryptionConfigurationNotFoundError":
            logger.warning(f"Бакет: {name}: Encryption - NO_CONFIGURATION")
            return "NO_CONFIGURATION"
        else:
            logger.warning(f"Бакет: {name}: Encryption - ERROR: {e}")
            return {"ERROR": e}
    
def bucket_cors(client: Any, name: str) -> str | dict[str, Any]:
    try:
        response = client.get_bucket_cors(Bucket=name)
        rule = response.get("CORSRules", [])

        flags = False

        for i in rule:
            allow = i.get("AllowedOrigins", [])

            if "*" in allow:
                flags = True
                break
        if flags:
            logger.warning(f"Бакет: {name}: Cors - DANGER")
            return "DANGER"
        logger.info(f"Бакет: {name}: Cors - SAFE")
        return "SAFE"
    except ClientError as e:
        if e.response['Error']['Code'] == "NoSuchCORSConfiguration":
            logger.warning(f"Бакет: {name}: Cors - NO_CONFIGURATION")
            return "NO_CONFIGURATION"
        else:
            logger.error(f"Бакет: {name}: Cors - ERROR: {e}")
            return {"ERROR": e}

def bucket_lifecycle(client: Any, name: str) -> str | dict[str, Any]:
    try:
        response = client.get_bucket_lifecycle_configuration(Bucket=name)
        logger.info(f"Бакет: {name}: lifecycle - {response}")
        return response
    except ClientError as e:
        if e.response['Error']['Code'] == "NoSuchLifecycleConfiguration":
            logger.warning(f"Бакет: {name}: lifecycle - NO_CONFIGURATION")
            return "NO_CONFIGURATION"
        else:
            logger.error(f"Бакет: {name}: lifecycle - ERROR: {e}")
            return {"ERROR": e}

def bucket_acl(client: Any, name: str) -> str | dict[str, Any]:
    try:
        dangerous_uri = {
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
        }
        response = client.get_bucket_acl(Bucket=name)
        grant = response.get("Grants", [])

        reports = []

        for i in grant:
            grantee = i.get("Grantee", {})
            if grantee.get("Type", "") == "Group":
                uri = grantee.get("URI", "")
                if uri in dangerous_uri:
                    reports.append({
                        "URI": uri,
                        "Permission": i.get("Permission", "")
                    })
        if reports:
            logger.warning(f"Бакет: {name}: Acl - DANGER")
            return {"DANGER": reports}
        logger.info(f"Бакет: {name}: Acl - SAFE")
        return "SAFE"
    except ClientError as e:
        if e.response['Error']['Code'] == "NoSuchBucketAcl":
            logger.warning(f"Бакет: {name}: Acl - NO_CONFIGURATION")
            return "NO_CONFIGURATION"
        else:
            logger.error(f"Бакет: {name}: Acl - ERROR: {e}")
            return {"ERROR": e} 

def bucket_mfa(client: Any, name: str) -> str | dict[str, Any]:
    try:
        response = client.get_bucket_versioning(Bucket=name)
        mfa = response.get("MFADelete", "")

        if not mfa:
            return "NO_CONFIGURATION"
        if mfa == "Disabled":
            logger.warning(f"Бакет: {name}: Mfa - DANGER")
            return "DANGER"
        logger.info(f"Бакет: {name}: Mfa - SAFE")
        return "SAFE"
    except ClientError as e:
        logger.error(f"Бакет: {name}: Mfa - ERROR: {e}")
        return {"ERROR": e}

def bucket_object(client: Any, name: str) -> str | dict[str, Any]:
    try:
        response = client.get_object_lock_configuration(Bucket=name)
        objects = response.get("ObjectLockConfiguration", {}).get("Rule", {}).get("DefaultRetention", {})

        mode = objects.get("Mode", "")
        days = objects.get("Days", "")

        info = {"Mode": mode, "Days": days}

        if mode == "GOVERNANCE":
            logger.warning(f"Бакет: {name}: Object - DANGER")
            return {"DANGER": info}
        logger.info(f"Бакет: {name}: Object - SAFE")
        return {"SAFE": info}
    except ClientError as e:
        if e.response['Error']['Code'] == "ObjectLockConfigurationNotFoundError":
            logger.warning(f"Бакет: {name}: Object - NO_CONFIGURATION")
            return "NO_CONFIGURATION"
        else:
            logger.error(f"Бакет: {name}: Object - ERROR: {e}")
            return {"ERROR": e}

def bucket_logging(client: Any, name: str) -> str | dict[str, Any]:
    try:
        response = client.get_bucket_logging(Bucket=name)
        log = response.get("LoggingEnabled", {})

        if not log:
            logger.warning(f"Бакет: {name}: Logging - NO_CONFIGURATION")
            return "NO_CONFIGURATION"
        logger.info(f"Бакет: {name}: Logging - SAFE")
        return "SAFE"
    except ClientError as e:
        logger.error(f"Бакет: {name}: Logging - ERROR: {e}")
        return {"ERROR": e}

def bucket_replication(clients: Any, name: str) -> str | dict[str, Any]:
    try:
        response = clients.get_bucket_replication(Bucket=name)
        replication = response.get("ReplicationConfiguration", {}).get("Rules", [])

        if not replication:
            logger.warning(f"Бакет: {name}: Replication - NO_CONFIGURATION")
            return "NO_CONFIGURATION"

        report = []
    
        for i in replication:
            statis = i.get("Status", "")
            ids = i.get("ID", "")

            if statis == "Disabled":
                report.append({
                    "Status": statis,
                    "Id": ids
                })
        if report:
            logger.warning(f"Бакет: {name}: Replication - DANGER")
            return {"DANGER": report}
        logger.info (f"Бакет: {name}: Replication - SAFE")
        return "SAFE"
    except ClientError as e:
        if e.response['Error']['Code'] == "ReplicationConfigurationNotFoundError":
            logger.warning(f"Бакет: {name}: Replication - NO_CONFIGURATION")
            return "NO_CONFIGURATION"
        else:
            logger.error(f"Бакет: {name}: Replication - ERROR: {e}")
            return {"ERROR": e}

def bucket_checkout() -> list[dict[str, Any]]:
    logger.info("Начало сканирование бакетов")
    clients = boto3_logging()
    reports = []
    bucket = bucket_get(folder_id)

    for i in bucket:
        name = i.get("name")

        all_reports={
            "Bucket_Name": name,
            "Policy": bucket_policy(clients, name),
            "Versioning": bucket_versioning(clients, name),
            "Encryption": bucket_encrriptyon(clients, name),
            "Cors": bucket_cors(clients, name),
            "Lifecycle": bucket_lifecycle(clients, name),
            "Acl": bucket_acl(clients, name),
            "Mfa": bucket_mfa(clients, name),
            "ObjectLock": bucket_object(clients, name),
            "Logging": bucket_logging(clients, name),
            "Replication": bucket_replication(clients, name)
        }
        reports.append(all_reports)
    logger.info(f"Сканирование завершено. Проверено бакетов: {len(reports)}")
    if reports:
        return reports
    return []


def bd_result(reports: list[dict[str, Any]]) -> None:
    
    try:
        logging.info("Начинаем подключаться к БД")
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            connect_timeout=5
        )
        
        cur = conn.cursor()
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_result_bucket(
                id SERIAL PRIMARY KEY,
                scan_date TIMESTAMP DEFAULT NOW(),
                bucket_name TEXT,
                policy TEXT,
                versioning TEXT,
                encryption TEXT,
                cors TEXT,
                lifecycle TEXT,
                acl TEXT,
                mfa TEXT,
                object_lock TEXT,
                logging TEXT,
                replication TEXT,
                full_report JSONB
            )
        """)
        
        for report in reports:
            cur.execute("""
                INSERT INTO scan_result_bucket(
                    bucket_name, policy, versioning, encryption, cors,
                    lifecycle, acl, mfa, object_lock, logging, replication, full_report
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                report.get("Bucket_Name"),
                str(report.get("Policy")),
                str(report.get("Versioning")),
                str(report.get("Encryption")),
                str(report.get("Cors")),
                str(report.get("Lifecycle")),
                str(report.get("Acl")),
                str(report.get("Mfa")),
                str(report.get("ObjectLock")),
                str(report.get("Logging")),
                str(report.get("Replication")),
                Json(report)
            ))

        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Сохранено {len(reports)} записей в БД")

    except Exception as e:
        logger.error(f"Ошибка сохранения в БД: {e}")
        
        
def main():
    report = bucket_checkout()

    if report:
        bd_result(report)
    logging.info(json.dumps(report, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    main()