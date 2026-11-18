#!/usr/bin/env bash
# Builds libiio (sanitized), the five fuzz harnesses and their -standalone reproducers, and the
# project's own CTest suite (normal flags) for mayhem/test.sh. Everything lands under build/ (gitignored).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT=/mayhem
mkdir -p build

# Backends under test: xml, emu and the ip client, plus iiod's server-side interpreters (libtinyiiod, and
# the daemon's own text/binary interpreter). No hardware backends, no avahi, no man pages.
COMMON_OPTS=(-GNinja -DWITH_IIOD=OFF -DWITH_USB_BACKEND=OFF -DWITH_SERIAL_BACKEND=OFF -DWITH_LOCAL_BACKEND=OFF
	-DWITH_MAN=OFF -DHAVE_DNS_SD=OFF -DWITH_EXAMPLES=OFF -DWITH_MODULES=OFF -DENABLE_PACKAGING=OFF
	-DWITH_XML_BACKEND=ON -DWITH_EMU_BACKEND=ON -DWITH_NETWORK_BACKEND=ON -DWITH_ZSTD=ON
	)

# 1) The sanitized project.
cmake -S . -B build/san "${COMMON_OPTS[@]}" -DWITH_IIOD_EMU=ON -DWITH_UTILS=OFF -DWITH_TESTS=OFF -DBUILD_SHARED_LIBS=OFF \
	-DCMAKE_C_FLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
cmake --build build/san -j"$MAYHEM_JOBS" --target iio iiod-responder tinyiiod

# 1b) The iiod daemon's sources (v0 text parser, interpreter, binary protocol), sanitized. Only its objects
# are used: the harness replaces iiod.c's main(). No libaio in the image, so iiod reads with poll(); the
# network and serial front ends are not built, the harness is the client connection.
# ops.c casts iio_device_get_attr & co. to a callback type with different pointer types; UBSan's `function`
# check halts on every attribute listing (READ <device>, READ ... INPUT <chn>) and nothing past it is
# reachable. Only that check is relaxed, and only in this tree; the other targets keep it.
UB_RELAX="-fno-sanitize=function"
cmake -S . -B build/iiod "${COMMON_OPTS[@]}" -DWITH_IIOD=ON -DWITH_AIO=OFF -DWITH_IIOD_V0_COMPAT=ON \
	-DWITH_IIOD_NETWORK=OFF -DWITH_IIOD_SERIAL=OFF \
	-DWITH_IIOD_EMU=OFF -DWITH_UTILS=OFF -DWITH_TESTS=OFF -DBUILD_SHARED_LIBS=OFF \
	-DCMAKE_C_FLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $UB_RELAX"
cmake --build build/iiod -j"$MAYHEM_JOBS" --target iiod
IIOD_OBJS=$(find build/iiod/iiod/CMakeFiles/iiod.dir -name '*.o' ! -name 'iiod.c.o' | sort)

# 2) Harnesses: each is compiled twice, against the libFuzzer engine and the run-once standalone driver.
python3 - <<'PY'
import os
res = "tests/resources/xmls"
def arr(name, data):
    body = ",".join(str(b) for b in data)
    return "static const unsigned char %s[] = {%s};\nstatic const unsigned long %s_len = %d;\n" % (name, body, name, len(data))
with open("build/fixtures.h", "w") as f:
    f.write(arr("fixture_xml", open(os.path.join(res, "fmcomms2.xml"), "rb").read()))
    f.write(arr("fixture_bin", open(os.path.join(res, "cf-ad9361-lpc_buf0.bin"), "rb").read()))
PY

LIBS="build/san/tinyiiod/libtinyiiod.a build/san/libiiod-responder.a build/san/libiio.a"
SYSLIBS="$(pkg-config --libs libxml-2.0 libzstd) -lpthread -lm"
INCS="-Iinclude -Itinyiiod -Ibuild/san $(pkg-config --cflags libxml-2.0) -Imayhem -Ibuild"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/standalone_main.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/lsan_off.o
# The two harnesses that drive iiod's responder link malloc_cap.o and wrap malloc (see malloc_cap.c).
$CC -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/malloc_cap.c -o build/malloc_cap.o
CAP_LINK="build/malloc_cap.o -Wl,--wrap=malloc"

for t in fuzz_xml_context fuzz_emu_context fuzz_ip_client fuzz_tinyiiod; do
	cap=""
	[ "$t" = fuzz_tinyiiod ] && cap="$CAP_LINK"
	$CC -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $INCS -c "mayhem/$t.c" -o "build/$t.o"
	$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "build/$t.o" build/lsan_off.o $cap \
		-Wl,--start-group $LIBS -Wl,--end-group $SYSLIBS -o "$OUT/$t"
	$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "build/$t.o" build/standalone_main.o build/lsan_off.o $cap \
		-Wl,--start-group $LIBS -Wl,--end-group $SYSLIBS -o "$OUT/$t-standalone"
done

# The iiod interpreter harness links the daemon's objects (above) instead of libtinyiiod, which carries its
# own copy of iiod/responder.c.
t=fuzz_iiod_interpreter
IIOD_INCS="-Iinclude -Iiiod -Ibuild/iiod $(pkg-config --cflags libxml-2.0) -Ibuild"
IIOD_LIBS="$IIOD_OBJS build/iiod/libiiod-responder.a build/iiod/libiio.a"
$CC -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $IIOD_INCS -c "mayhem/$t.c" -o "build/$t.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "build/$t.o" build/lsan_off.o $CAP_LINK \
	-Wl,--start-group $IIOD_LIBS -Wl,--end-group $SYSLIBS -o "$OUT/$t"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "build/$t.o" build/standalone_main.o build/lsan_off.o $CAP_LINK \
	-Wl,--start-group $IIOD_LIBS -Wl,--end-group $SYSLIBS -o "$OUT/$t-standalone"

# 3) The project's own API tests (and the iio_attr CLI test), normal flags, for mayhem/test.sh.
cmake -S . -B build/tests "${COMMON_OPTS[@]}" -DWITH_IIOD_EMU=OFF -DWITH_UTILS=ON -DWITH_TESTS=ON -DBUILD_SHARED_LIBS=ON \
	-DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build build/tests -j"$MAYHEM_JOBS"
