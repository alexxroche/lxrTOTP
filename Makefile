lxrtotp: lxrtotp.c
	$(CC) -Wall -o $@ $<
portable: lxrtotp.c
	gcc -static -Wall -o $@ $<
totp: lxrtotp.c
	gcc -Wall -o $@ $<
totp_small: lxrtotp.c
	gcc -O -Wall -o totp_small lxrtotp.c
totp_small_static: lxrtotp.c
	gcc -static -O -Wall -o totp_small_static lxrtotp.c
