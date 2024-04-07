from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
from cassandra.query import SimpleStatement
import json
import datetime
import os


#boilerplate code to connect to cassandra
def connect_to_cassandra():
    # Extracting required secrets
    from dotenv import load_dotenv
    load_dotenv()
    CLIENT_ID = os.environ["clientId"]
    CLIENT_SECRET = os.environ["secret"]

    # Cassandra cloud configuration
    cloud_config = {"secure_connect_bundle": "secure-connect-phishing-detection.zip"}

    # Authentication provider
    auth_provider = PlainTextAuthProvider(CLIENT_ID, CLIENT_SECRET)

    # Connect to Cassandra cluster
    cluster = Cluster(cloud=cloud_config, auth_provider=auth_provider)
    session = cluster.connect()

    # Switch to the keyspace
    session.set_keyspace("phishingdetectionlog")
    
    return cluster, session

def add_table():
    cluster, session = connect_to_cassandra()
    # columns_definition = ', '.join([f"{column_name} {column_type}" for column_name, column_type in columns.items()])
    create_table_query = """
    CREATE TABLE IF NOT EXISTS phishingdetectionlog.phishing_data (
        ip text,
        time timestamp,
        url text,
        pred text,
        PRIMARY KEY (ip, time)
    );"""

    session.execute(create_table_query)
    
    cluster.shutdown()

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

if __name__ == "__main__":
    add_table()