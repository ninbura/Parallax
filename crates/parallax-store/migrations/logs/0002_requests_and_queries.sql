-- Records from the HTTPS proxy and the DNS server (kinds request, refused
-- and query). Never a URL path, never the addresses a DNS answer gave.

-- The site a proxied request was for, or the name a DNS query asked.
ALTER TABLE records ADD COLUMN hostname TEXT;
-- A proxied request's method and the HTTP status it was answered with.
ALTER TABLE records ADD COLUMN method TEXT;
ALTER TABLE records ADD COLUMN status INTEGER;
-- A DNS query's type (A, AAAA, ...).
ALTER TABLE records ADD COLUMN query_type TEXT;
-- How a DNS query was answered, or why the proxy refused.
ALTER TABLE records ADD COLUMN outcome TEXT;
