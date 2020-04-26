# dnsd

Work in progress.

Test:

	dig ns1.zedns.net @127.0.0.1 -p 8053

# Database buckets

## record

Dns zones are stored into "zone" bucket.

* Key: 16 bytes zone prefix (binary), followed by the name in reverse order, followed by a zero byte and the type of record (2 bytes)
* Value: timestamp (12 bytes) + serialized list of RData

## domain

* Key: optional IP address on which packet has been received (16 bytes) + domain
* Value: timestamp (12 bytes) + value
