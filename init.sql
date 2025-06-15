CREATE TABLE IF NOT EXISTS companies (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS subdomains (
    id SERIAL PRIMARY KEY,
    company_id INTEGER REFERENCES companies(id),
    subdomain TEXT,
    UNIQUE (company_id, subdomain)
);

CREATE TABLE IF NOT EXISTS scope_domains (
    id SERIAL PRIMARY KEY,
    company_id INTEGER REFERENCES companies(id),
    domain TEXT,
    in_scope BOOLEAN,
    UNIQUE (company_id, domain)
);

CREATE TABLE IF NOT EXISTS ips (
    id SERIAL PRIMARY KEY,
    company_id INTEGER REFERENCES companies(id),
    address TEXT,
    UNIQUE (company_id, address)
);

CREATE TABLE IF NOT EXISTS asns (
    id SERIAL PRIMARY KEY,
    company_id INTEGER REFERENCES companies(id) ON DELETE CASCADE,
    asn TEXT NOT NULL,
    UNIQUE(company_id, asn)
);

