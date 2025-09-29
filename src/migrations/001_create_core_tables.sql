CREATE TABLE IF NOT EXISTS tabs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tab_name VARCHAR(100) NOT NULL,
    host_name VARCHAR(100),
    proto_file_path VARCHAR(100),
    proto_additional_path VARCHAR(200),
    method_name VARCHAR(100),
    saved_tab BOOLEAN DEFAULT 0,
    secure BOOLEAN DEFAULT 0,
    request_message TEXT,
    collection_id INTEGER default 0,
    env_id INTEGER DEFAULT -1
);

CREATE TABLE IF NOT EXISTS creds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tab_id INTEGER NOT NULL DEFAULT -1,
    client_certificate_crt VARCHAR(100),
    client_key_file VARCHAR(100),
    ca_certificate_root_ca VARCHAR(100),
    pem_certificate VARCHAR(100),
    host_name VARCHAR(100),
    env_id INTEGER DEFAULT -1
);

CREATE TABLE IF NOT EXISTS meta (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tab_id INTEGER NOT NULL DEFAULT -1,
    name VARCHAR(100),
    value VARCHAR(100),
    description VARCHAR(100),
    env_id INTEGER DEFAULT -1
);

CREATE TABLE IF NOT EXISTS auth_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tab_id INTEGER NOT NULL DEFAULT -1,
    name VARCHAR(100),
    data TEXT,
    env_id INTEGER DEFAULT -1
);

CREATE TABLE IF NOT EXISTS env_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    env_name VARCHAR(100) DEFAULT 'global'
);

CREATE TABLE IF NOT EXISTS env_variables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    env_var_name VARCHAR(100) DEFAULT '',
    env_var_value VARCHAR(100) DEFAULT '',
    env_var_type VARCHAR(100) DEFAULT 'default',
    env_id INTEGER DEFAULT -1
);

CREATE TABLE IF NOT EXISTS collection (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collection_name VARCHAR(100) DEFAULT ''
);
