from database.database import SQLiteManager
from executer.helper import helper
from typing import List, Tuple, Optional
import sqlite3
import sys, os
from pathlib import Path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from constants import *

class queries(SQLiteManager, helper):
    def __init__(self, db_path = "grpc_gui.db", migrations_dir = "./migrations"):
        db_path = os.path.join(Path.cwd(), 'database', 'grpc_gui.db')
        SQLiteManager.__init__(self, db_path, migrations_dir)
        helper.__init__(self)
    
    # ====================
    # Insert Functions
    # ====================

    def insert_tab_entry(self, tab_data: dict) -> int:
        try:
            cur = self.execute("""
                INSERT INTO tabs (
                    tab_name, host_name, proto_file_path, proto_additional_path,
                    method_name, saved_tab, request_message, env_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tab_data["tab_name"],
                tab_data.get("host_name"),
                tab_data.get("proto_file_path"),
                tab_data.get("proto_additional_path"),
                tab_data.get("method_name"),
                tab_data.get("saved_tab", 0),
                tab_data.get("request_message", None),
                tab_data.get("env", GLOBAL_ENV),
            ))
            
            return cur
        except Exception as e:
            self.log(function_name='insert_tab_entry', args=[tab_data], exception=e)

    def insert_creds_entry(self, tab_id: int, creds_data: dict) -> None:
        try:
            if creds_data:
                sql = """
                INSERT INTO creds (
                tab_id, client_certificate_crt, client_key_file,
                ca_certificate_root_ca, pem_certificate, host_name, env_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """
                
                params = (
                    tab_id,
                    creds_data.get("client_certificate"),
                    creds_data.get("client_key"),
                    creds_data.get("ca_certificate"),
                    creds_data.get("pem_certificate", None),
                    creds_data.get("host"),
                    creds_data.get("env", GLOBAL_ENV),
                    )
                
                cur = self.execute(sql, params)
                
                return cur
                
        except Exception as e:
            self.log(function_name='insert_creds_entry', args=[tab_id, creds_data], exception=e)

    def insert_meta_entries(self, tab_id: int, meta_data: List[dict]) -> None:
        try:
            if meta_data:
                sql = """
                INSERT INTO meta (tab_id, name, value, description, env_id)
                VALUES (?, ?, ?, ?, ?)
                """

                params = [(tab_id, m.get("name"), m.get("value"), m.get("description"), m.get("env", GLOBAL_ENV),)
                        for m in meta_data
                        ]
                cur = self.execute_many(sql, params)
                
                return cur
        except Exception as e:
            self.log(function_name='insert_meta_entries', args=[tab_id, meta_data], exception=e)

    def insert_auth_data_entries(self, tab_id: int, auth_data_list: List[dict]) -> None:
        try:
            if auth_data_list:
                cur = self.execute_many("""
                    INSERT INTO auth_data (tab_id, name, data, env_id)
                    VALUES (?, ?, ?, ?)
                """, [
                    (tab_id, a.get("name"), a.get("data"), a.get("env", GLOBAL_ENV),)
                    for a in auth_data_list
                ])
                
                return cur
        except Exception as e:
            self.log(function_name='insert_auth_data_entries', args=[tab_id, auth_data_list], exception=e)



    def insert_tab_transactional(self, tab_data, creds_data=None, meta_data=None, auth_data_list=None) -> int:
        try:
            with self:
                tab_id = self.insert_tab_entry(tab_data)
                self.insert_creds_entry(tab_id, creds_data or {})
                self.insert_meta_entries(tab_id, meta_data or [])
                self.insert_auth_data_entries(tab_id, auth_data_list or [])
                return tab_id
        except Exception as e:
            self.log(function_name='insert_tab_transactional', args=[tab_id, tab_data, creds_data, meta_data, auth_data_list], exception=e)

    # ====================
    # Update Functions
    # ====================

    def update_tab_entry(self, tab_id: int, tab_data: dict) -> None:
        try:
            self.cursor.execute("""
                UPDATE tabs SET
                    tab_name = ?, host_name = ?, proto_file_path = ?,
                    proto_additional_path = ?, method_name = ?, saved_tab = ?, request_message = ?
                WHERE id = ?
            """, (
                tab_data["tab_name"],
                tab_data.get("host_name"),
                tab_data.get("proto_file_path"),
                tab_data.get("proto_additional_path"),
                tab_data.get("method_name"),
                tab_data.get("saved_tab", 0),
                tab_data.get("request_message"),
                tab_id
            ))
        except Exception as e:
            self.log(function_name='update_tab_entry', args=[tab_id, tab_data], exception=e)

    def update_creds_entry(self, id: int, creds_data: dict) -> None:
        try:
            return self.execute("""
                UPDATE creds SET
                    client_certificate_crt = ?, client_key_file = ?,
                    ca_certificate_root_ca = ?, pem_certificate = ?,
                    host_name =? , env_id = ?
                WHERE id = ?
            """, (
                creds_data.get("client_certificate"),
                creds_data.get("client_key"),
                creds_data.get("ca_certificate"),
                creds_data.get("pem_certificate"),
                creds_data.get("host"),
                creds_data.get("env", GLOBAL_ENV),
                id
            ))
        except Exception as e:
            self.log(function_name='update_creds_entry', args=[id, creds_data], exception=e)

    def update_meta_entries(self, tab_id: int, meta_data: List[dict]) -> None:
        try:
            self.cursor.execute("DELETE FROM meta WHERE tab_id = ?", (tab_id,))
            self.insert_meta_entries(tab_id, meta_data)
        except Exception as e:
            self.log(function_name='update_meta_entries', args=[tab_id, meta_data], exception=e)

    def update_auth_data_entries(self, tab_id: int, auth_data_list: List[dict]) -> None:
        try:
            self.cursor.execute("DELETE FROM auth_data WHERE tab_id = ?", (tab_id,))
            self.insert_auth_data_entries(tab_id, auth_data_list)
        except Exception as e:
            self.log(function_name='update_auth_data_entries', args=[tab_id, auth_data_list], exception=e)

    def update_tab_transactional(self, tab_id: int, tab_data, creds_data=None, meta_data=None, auth_data_list=None) -> None:
        try:
            with self:
                self.update_tab_entry(tab_id, tab_data)
                self.update_creds_entry(tab_id, creds_data or {})
                self.update_meta_entries(tab_id, meta_data or [])
                self.update_auth_data_entries(tab_id, auth_data_list or [])
        except Exception as e:
            self.log(function_name='update_tab_transactional', args=[tab_id, tab_data, creds_data, meta_data, auth_data_list], exception=e)

    # ====================
    # Select Functions
    # ====================

    def get_tab_by_id(self, tab_id: int) -> Optional[sqlite3.Row]:
        try:
            return self.fetchone("SELECT * FROM tabs WHERE id = ?", (tab_id,))
        except Exception as e:
            self.log(function_name='get_tab_by_id', args=[tab_id], exception=e)

    def get_all_tabs(self) -> List[sqlite3.Row]:
        try:
            return self.fetchall("SELECT id, tab_name FROM tabs ORDER BY id")
        except Exception as e:
            self.log(function_name='get_all_tabs', args=[], exception=e)

    def get_creds_by_tab_id(self, tab_id: int) -> Optional[sqlite3.Row]:
        try:
            return self.fetchone("SELECT * FROM creds WHERE tab_id = ?", (tab_id,))
        except Exception as e:
            self.log(function_name='get_creds_by_tab_id', args=[tab_id], exception=e)

    def get_meta_by_tab_id(self, tab_id: int) -> List[sqlite3.Row]:
        try:
            return self.fetchall("SELECT * FROM meta WHERE tab_id = ?", (tab_id,))
        except Exception as e:
            self.log(function_name='get_meta_by_tab_id', args=[tab_id], exception=e)

    def get_auth_data_by_tab_id(self, tab_id: int) -> List[sqlite3.Row]:
        try:
            return self.fetchall("SELECT * FROM auth_data WHERE tab_id = ?", (tab_id,))
        except Exception as e:
            self.log(function_name='get_auth_data_by_tab_id', args=[tab_id], exception=e)

    def get_saved_tabs(self) -> List[sqlite3.Row]:
        try:
            return self.fetchall("SELECT * FROM tabs WHERE saved_tab = 1 ORDER BY id")
        except Exception as e:
            self.log(function_name='get_saved_tabs', args=[], exception=e)

    def search_tabs_by_name(self, name_fragment: str) -> List[sqlite3.Row]:
        try:
            return self.fetchall("SELECT * FROM tabs WHERE tab_name LIKE ?", (f"%{name_fragment}%",))
        except Exception as e:
            self.log(function_name='search_tabs_by_name', args=[name_fragment], exception=e)

    def get_tab_count(self) -> int:
        try:
            row = self.fetchone("SELECT COUNT(*) as count FROM tabs")
            return row["count"] if row else 0
        except Exception as e:
            self.log(function_name='get_tab_count', args=[], exception=e)

    def row_to_dict(self, row: sqlite3.Row) -> dict:
        try:
            return dict(row) if row else {}
        except Exception as e:
            self.log(function_name='row_to_dict', args=[], exception=e)
    
    def get_tables(self):
        try:
            return self.fetchall("SELECT name FROM sqlite_master WHERE type='table';")
        except Exception as e:
            self.log(function_name='get_tables', args=[], exception=e)
    
    def get_creds(self, where = {}):
        try:
            if ('host' in where):
                sql = """SELECT * from creds where host_name = ?"""
                params = (str(where['host']),)
                return self.fetchall(sql, params)
            else:
                sql = """SELECT * from creds;"""
                return self.fetchall(sql)
        except Exception as e:
            self.log(function_name='get_creds', args=[], exception=e)
    
    def get_tab_all_data(self, tab_id):
        try:
            sql = """SELECT \
                t.id AS tab_id,\
                t.tab_name,\
                t.host_name AS tab_host,\
                t.proto_file_path,\
                t.proto_additional_path,\
                t.method_name,\
                t.saved_tab,\
                t.request_message,\
                t.env_id AS tab_env_id,\
                a.id AS auth_id,\
                a.name AS auth_name,\
                a.data AS auth_data,\
                a.env_id AS auth_env_id,\
                e.id AS env_id,\
                e.env_name\
                FROM tabs t\
                LEFT JOIN auth_data a ON t.id = a.tab_id\
                LEFT JOIN env_data e ON e.id = t.env_id\
                WHERE t.id = ?;"""
            
            params = (int(tab_id),)
            return self.fetchall(sql, params)
        except Exception as e:
            self.log(function_name='get_tab_all_data', args=[tab_id], exception=e)
        
    
    # ====================
    # Delete Functions
    # ====================
    
    def delete_creds_entry(self, tab_id: int) -> None:
        try:
            cur = self.execute("DELETE FROM creds WHERE id = ?", (tab_id,))
            return cur.rowcount
        except Exception as e:
            self.log(function_name='delete_creds_entry', args=[tab_id], exception=e)

    def delete_meta_entries(self, tab_id: int) -> None:
        try:
            cur = self.execute("DELETE FROM meta WHERE tab_id = ?", (tab_id,))
            return cur.rowcount
        except Exception as e:
            self.log(function_name='delete_meta_entries', args=[tab_id], exception=e)

    def delete_auth_data_entries(self, tab_id: int) -> None:
        try:
            cur = self.execute("DELETE FROM auth_data WHERE tab_id = ?", (tab_id,))
            return cur.rowcount
        except Exception as e:
            self.log(function_name='delete_auth_data_entries', args=[tab_id], exception=e)

    def delete_tab_entry(self, tab_id: int) -> None:
        try:
            cur = self.execute("DELETE FROM tabs WHERE id = ?", (tab_id,))
            return cur.rowcount
        except Exception as e:
            self.log(function_name='delete_tab_entry', args=[tab_id], exception=e)

    def delete_tab_transactional(self, tab_id: int) -> None:
        try:
            """Delete tab and all related data in one transaction"""
            with self:
                deleted = {
                    "creds": self.delete_creds_entry(tab_id),
                    "meta": self.delete_meta_entries(tab_id),
                    "auth_data": self.delete_auth_data_entries(tab_id),
                    "tab": self.delete_tab_entry(tab_id)
                }
            return deleted
        except Exception as e:
            self.log(function_name='delete_tab_transactional', args=[tab_id], exception=e)
