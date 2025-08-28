import sqlite3
import os
from typing import List, Tuple, Optional
from executer.helper import helper

class SQLiteManager:
    def __init__(self, db_path: str = "grpc_gui.db", migrations_dir: str = "./migrations"):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self.migrations_dir = migrations_dir
        self.helpercls = helper()

        # Ensure migrations folder exists
        os.makedirs(self.migrations_dir, exist_ok=True)

        # Auto-connect and apply migrations if DB is new
        db_already_exists = os.path.isfile(self.db_path)
        self.connect()
        if not db_already_exists:
            print(f"Database {self.db_path} not found. Creating and applying migrations...")
            self.run_migrations()
        else:
            self._ensure_migrations_table()

    def connect(self):
        try:
            if not self.conn:
                self.conn = sqlite3.connect(
                    self.db_path,
                    timeout=10,  # wait for lock up to 10s
                    isolation_level=None  # autocommit unless in context manager
                )
                self.conn.row_factory = sqlite3.Row
                self.cursor = self.conn.cursor()

                # Enable WAL mode for fewer locks
                self.conn.execute("PRAGMA journal_mode=WAL;")
                self.conn.execute("PRAGMA foreign_keys = ON;")
        except Exception as e:
            self.helpercls.log('connect', [], exception=e)
    def close(self):
        try:
            if self.conn:
                self.conn.close()
                self.conn = None
                self.cursor = None
        except Exception as e:
            self.helpercls.log('close', [], exception=e)

    def execute(self, query: str, params: Optional[Tuple] = None) -> int:
        """Executes a single query and returns lastrowid."""
        self.connect()
        try:
            cur = self.cursor.execute(query, params or ())
            self.conn.commit()

            sql_type = query.strip().split()[0].upper()
            if sql_type == "INSERT":
                return cur.lastrowid
            else:  # UPDATE or DELETE
                return cur
            
        except sqlite3.OperationalError as e:
            self.helpercls.log('execute', [query, params], exception=e)
            if "locked" in str(e).lower():
                print(f"[LOCKED] Query could not execute:\nSQL: {query}\nParams: {params}")
            raise

    def fetchall(self, query: str, params: Optional[Tuple] = None) -> List[dict]:
        try:
            self.connect()
            self.cursor.execute(query, params or ())
            rows = self.cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            self.helpercls.log('fetchall', [query, params], exception=e)

    def fetchone(self, query: str, params: Optional[Tuple] = None) -> Optional[dict]:
        try:
            self.connect()
            self.cursor.execute(query, params or ())
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            self.helpercls.log('fetchone', [query, params], exception=e)

    def execute_many(self, query: str, param_list: List[Tuple]) -> None:
        self.connect()
        try:
            cur = self.cursor.executemany(query, param_list)
            self.conn.commit()
            return cur
        except sqlite3.OperationalError as e:
            self.helpercls.log('execute_many', [query, param_list], exception=e)
            if "locked" in str(e).lower():
                print(f"[LOCKED] Query could not execute:\nSQL: {query}\nParams: {param_list}")
            raise

    def __enter__(self):
        try:
            self.connect()
            self.conn.execute("BEGIN")
            return self
        except Exception as e:
            self.helpercls.log('__enter__', [], exception=e)

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
        except Exception as e:
            self.helpercls.log('__exit__', [], exception=e)

    def run_migrations(self):
        try:
            self.connect()
            self._ensure_migrations_table()

            applied = set(row["filename"] for row in self.fetchall("SELECT filename FROM migrations"))
            all_files = sorted(f for f in os.listdir(self.migrations_dir) if f.endswith(".sql"))

            for file in all_files:
                if file not in applied:
                    path = os.path.join(self.migrations_dir, file)
                    with open(path, "r") as f:
                        sql = f.read()

                    self.cursor.executescript(sql)
                    self.cursor.execute("INSERT INTO migrations (filename) VALUES (?)", (file,))
                    self.conn.commit()
        except Exception as e:
            self.helpercls.log('run_migrations', [], exception=e)

    def _ensure_migrations_table(self):
        try:
            self.execute("""
            CREATE TABLE IF NOT EXISTS migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT UNIQUE NOT NULL,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
        except Exception as e:
            self.helpercls.log('_ensure_migrations_table', [], exception=e)

#SQLiteManagercls = SQLiteManager()








