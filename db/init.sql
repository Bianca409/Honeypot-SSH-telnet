CREATE DATABASE IF NOT EXISTS honeypot_db;
USE honeypot_db;

-- Tabel pentru încercările de login pe SSH și Telnet
CREATE TABLE IF NOT EXISTS auth_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    protocol VARCHAR(10) NOT NULL, -- 'SSH' sau 'TELNET'
    source_ip VARCHAR(45) NOT NULL,
    source_port INT NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    status VARCHAR(30) DEFAULT 'REJECTED'
);

-- Tabel pentru comenzile rulate în fake shell
CREATE TABLE IF NOT EXISTS shell_commands (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) NOT NULL,
    command TEXT NOT NULL
);
