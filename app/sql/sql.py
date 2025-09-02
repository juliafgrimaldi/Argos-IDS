import sqlite3

DB_FILE = "traffic.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS flows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time REAL,
        dpid INTEGER,
        in_port INTEGER,
        eth_src TEXT,
        eth_dst TEXT,
        packets INTEGER,
        bytes INTEGER,
        duration_sec INTEGER,
        label INTEGER
    )
    """)
    conn.commit()
    conn.close()

def save_flow(rows):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.executemany("""
    INSERT INTO flows (time, dpid, in_port, eth_src, eth_dst, packets, bytes, duration_sec, label)
    VALUES (:time, :dpid, :in_port, :eth_src, :eth_dst, :packets, :bytes, :duration_sec, :label)
    """, rows)
    conn.commit()
    conn.close()
