proxy_cache: server.c
	gcc server.c -o proxy_cache -lcrypto -lpthread
