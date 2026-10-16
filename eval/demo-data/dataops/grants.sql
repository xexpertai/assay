-- demo migration (fictional)
GRANT SELECT ON ALL TABLES IN SCHEMA analytics TO PUBLIC;
CREATE USER etl_loader IDENTIFIED BY 'Dem0LoaderPw42';
