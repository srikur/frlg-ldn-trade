.PHONY: mac-probe mac-listen native-test

# Build only. Run the probe separately; never run make under sudo.
mac-probe: build/macos-probe

build/macos-probe: native/macos_probe.m
	mkdir -p build
	xcrun clang -O2 -Wall -Wextra -Werror -fobjc-arc \
		-framework Foundation -framework CoreWLAN -framework IOKit -lpcap \
		$< -o $@

mac-listen: build/macos-listen

build/macos-listen: native/macos_listen.m native/ldn_observation.h native/probe_frame.h native/auth_frame.h
	mkdir -p build
	xcrun clang -O2 -Wall -Wextra -Werror -fobjc-arc \
		-framework Foundation -framework CoreWLAN -lpcap $< -o $@

native-test: build/test-ldn-observation build/test-auth-frame build/test-macos-listen
	./build/test-ldn-observation
	./build/test-auth-frame
	./build/test-macos-listen

build/test-ldn-observation: tests/test_ldn_observation.c native/ldn_observation.h native/probe_frame.h
	mkdir -p build
	xcrun clang -Wall -Wextra -Werror -fsanitize=address,undefined $< -o $@

build/test-auth-frame: tests/test_auth_frame.c native/auth_frame.h native/ldn_observation.h
	mkdir -p build
	xcrun clang -Wall -Wextra -Werror -fsanitize=address,undefined $< -o $@

build/test-macos-listen: tests/test_macos_listen.m native/macos_listen.m native/ldn_observation.h native/probe_frame.h native/auth_frame.h
	mkdir -p build
	xcrun clang -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fobjc-arc \
		-framework Foundation -framework CoreWLAN -lpcap $< -o $@
