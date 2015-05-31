preinstall:
	(git clone https://chromium.googlesource.com/external/gyp.git tools/gyp || \
		echo 'gyp already checked out')
	./gyp_bud
	make -C out/ -j
	node npm/locate.js

.PHONY: preinstall
