import sqlite3

DATABASE = "phishguard.db"


def init_db():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            sender TEXT,

            subject TEXT,

            domain TEXT,

            threat_score INTEGER,

            risk TEXT,

            vt_reputation TEXT,

            country TEXT,

            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)

    conn.commit()
    conn.close()


def save_analysis(results):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""

        INSERT INTO analysis(

            sender,
            subject,
            domain,
            threat_score,
            risk,
            vt_reputation,
            country

        )

        VALUES(?,?,?,?,?,?,?)

    """, (

        results["From"],
        results["Subject"],
        results["Domain"],
        results["ThreatScore"],
        results["Risk"],
        results["VT_Reputation"],
        results["Country"]

    ))

    conn.commit()
    conn.close()


def get_history():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""

        SELECT *

        FROM analysis

        ORDER BY analyzed_at DESC

    """)

    rows = cursor.fetchall()

    conn.close()

    return rows
