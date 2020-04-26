# dnsd

Work in progress.

Test:

	dig ns1.zedns.net @127.0.0.1 -p 8053

# Database buckets

## record

Dns zones are stored into "zone" bucket. The key is a 16 bytes zone prefix (binary), followed by the name in reverse order, followed by the type of record.

## domain

Key is IP address on which packet has been received (16 bytes) + domain, or just domain (if first is not set, as a catch all). Value is zone id (16 bytes) + timestamp (12 bytes)
