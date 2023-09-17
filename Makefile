proxy_cache: proxy_server.c
	gcc proxy_server.c -o proxy_cache -lcrypto -lpthread
