CREATE ROLE reporting_ro;
GRANT USAGE ON SCHEMA reporting TO reporting_ro;
GRANT SELECT ON reporting.daily_sales TO reporting_ro;
CREATE USER reporter WITH PASSWORD 'changeme';
