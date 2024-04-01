from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
from cassandra.query import SimpleStatement
import json
import datetime

#boilerplate code to connect to cassandra
def connect_to_cassandra():
    # Load secrets from JSON file
    with open("Phishing_Domain_Detection-token.json") as f:
        secrets = json.load(f)

    # Extracting required secrets
    CLIENT_ID = secrets["clientId"]
    CLIENT_SECRET = secrets["secret"]

    # Cassandra cloud configuration
    cloud_config = {"secure_connect_bundle": "secure-connect-phishing-domain-detection.zip"}

    # Authentication provider
    auth_provider = PlainTextAuthProvider(CLIENT_ID, CLIENT_SECRET)

    # Connect to Cassandra cluster
    cluster = Cluster(cloud=cloud_config, auth_provider=auth_provider)
    session = cluster.connect()

    # Switch to the keyspace
    session.set_keyspace("log_data")
    
    return cluster, session

def add_entry(ip, time, url, pred):
    cluster, session = connect_to_cassandra()
    
    # Insert data into table
    insert_query = session.prepare(
        "INSERT INTO phishing_data (ip, time, url, pred) VALUES (?, ?, ?, ?)"
    )
    session.execute(insert_query, (ip, time, url, pred))
    
    cluster.shutdown()

def fetch_all_entries():
    cluster, session = connect_to_cassandra()

    select_query = session.prepare("SELECT * FROM phishing_data")
    result_set = session.execute(select_query)

    entries = []
    for row in result_set:
        entry = {
            "ip": row.ip,
            "time": row.time,
            "url": row.url,
            "pred": row.pred
        }
        entries.append(entry)

    cluster.shutdown()

    return entries
