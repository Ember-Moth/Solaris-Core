#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ABI=${1:-arm64-v8a}
OUTPUT_DIR=${2:-"$ROOT_DIR/build-android/install/$ABI"}
NDK_ROOT=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}
ANDROID_API=${ANDROID_API:-24}
WORK_DIR=${SOLARIS_CORE_ANDROID_WORK_DIR:-"$ROOT_DIR/build-android/work/$ABI"}
BORINGSSL_REPOSITORY=${BORINGSSL_REPOSITORY:-https://boringssl.googlesource.com/boringssl}
BORINGSSL_COMMIT=922c15f36cc75db5af33c46f9ea8934553fb808e
TOOLCHAIN="$NDK_ROOT/build/cmake/android.toolchain.cmake"
NDK_HOST_TAG=${APROXY_NDK_HOST_TAG:-}

if [ -z "$NDK_ROOT" ]; then
    echo "Android NDK is not configured; set ANDROID_NDK_HOME or ANDROID_NDK_ROOT" >&2
    exit 1
fi

if [ -z "$NDK_HOST_TAG" ]; then
    NDK_PREBUILT=$(find "$NDK_ROOT/toolchains/llvm/prebuilt" \
        -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | \
        sort | head -n 1)
else
    NDK_PREBUILT="$NDK_ROOT/toolchains/llvm/prebuilt/$NDK_HOST_TAG"
fi
NDK_BIN="$NDK_PREBUILT/bin"

STRIP_TOOL=${SOLARIS_ANDROID_STRIP_BIN:-${APROXY_NDK_STRIP_BIN:-}}
STRIP_MODE=strip
if [ -z "$STRIP_TOOL" ]; then
    if [ -x "$NDK_BIN/llvm-strip" ]; then
        STRIP_TOOL="$NDK_BIN/llvm-strip"
    else
        STRIP_TOOL="$NDK_BIN/llvm-objcopy"
        STRIP_MODE=objcopy
    fi
else
    case "$(basename -- "$STRIP_TOOL")" in
        *objcopy*) STRIP_MODE=objcopy ;;
    esac
fi

ELF_INSPECTOR=${SOLARIS_ANDROID_ELF_INSPECTOR_BIN:-${APROXY_NDK_ELF_INSPECTOR_BIN:-}}
ELF_INSPECTOR_MODE=readelf
if [ -z "$ELF_INSPECTOR" ] && [ -n "${SOLARIS_ANDROID_READELF_BIN:-}" ]; then
    ELF_INSPECTOR=$SOLARIS_ANDROID_READELF_BIN
elif [ -z "$ELF_INSPECTOR" ] && [ -n "${SOLARIS_ANDROID_READOBJ_BIN:-}" ]; then
    ELF_INSPECTOR=$SOLARIS_ANDROID_READOBJ_BIN
    ELF_INSPECTOR_MODE=readobj
fi
if [ -z "$ELF_INSPECTOR" ]; then
    if [ -x "$NDK_BIN/llvm-readelf" ]; then
        ELF_INSPECTOR="$NDK_BIN/llvm-readelf"
    else
        ELF_INSPECTOR="$NDK_BIN/llvm-readobj"
        ELF_INSPECTOR_MODE=readobj
    fi
else
    case "$(basename -- "$ELF_INSPECTOR")" in
        *readobj*) ELF_INSPECTOR_MODE=readobj ;;
    esac
fi

if [ ! -f "$TOOLCHAIN" ]; then
    echo "Android NDK toolchain not found: $TOOLCHAIN" >&2
    exit 1
fi
if [ ! -x "$STRIP_TOOL" ]; then
    echo "Android NDK strip tool not found; expected llvm-strip or llvm-objcopy under: $NDK_BIN" >&2
    exit 1
fi
if [ ! -x "$ELF_INSPECTOR" ]; then
    echo "Android NDK ELF inspector not found; expected llvm-readelf or llvm-readobj under: $NDK_BIN" >&2
    exit 1
fi
case "$OUTPUT_DIR" in
    ""|/) echo "Refusing unsafe Android output directory: $OUTPUT_DIR" >&2; exit 1 ;;
esac

mkdir -p "$WORK_DIR"
BORINGSSL_SOURCE="$WORK_DIR/boringssl-src"
BORINGSSL_BUILD="$WORK_DIR/boringssl-build"
BORINGSSL_INSTALL="$WORK_DIR/boringssl-install"

if [ ! -d "$BORINGSSL_SOURCE/.git" ]; then
    mkdir -p "$BORINGSSL_SOURCE"
    git -C "$BORINGSSL_SOURCE" init
    git -C "$BORINGSSL_SOURCE" remote add origin "$BORINGSSL_REPOSITORY"
fi
if ! git -C "$BORINGSSL_SOURCE" cat-file -e "$BORINGSSL_COMMIT^{commit}" 2>/dev/null; then
    echo "Fetching pinned BoringSSL source: $BORINGSSL_COMMIT"
    git -C "$BORINGSSL_SOURCE" fetch --depth 1 origin "$BORINGSSL_COMMIT"
fi
if [ "$(git -C "$BORINGSSL_SOURCE" rev-parse HEAD 2>/dev/null || true)" != "$BORINGSSL_COMMIT" ] || \
   ! git -C "$BORINGSSL_SOURCE" apply --reverse --check \
       "$ROOT_DIR/third_party/boringssl-reality.patch" 2>/dev/null; then
    git -C "$BORINGSSL_SOURCE" checkout --detach "$BORINGSSL_COMMIT"
    git -C "$BORINGSSL_SOURCE" reset --hard "$BORINGSSL_COMMIT"
    git -C "$BORINGSSL_SOURCE" clean -fd
    git -C "$BORINGSSL_SOURCE" apply "$ROOT_DIR/third_party/boringssl-reality.patch"
fi

cmake -S "$BORINGSSL_SOURCE" -B "$BORINGSSL_BUILD" -GNinja \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DANDROID_ABI="$ABI" \
    -DANDROID_PLATFORM="android-$ANDROID_API" \
    -DANDROID_STL=c++_shared \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DBUILD_SHARED_LIBS=OFF
cmake --build "$BORINGSSL_BUILD" --target crypto ssl

rm -rf "$BORINGSSL_INSTALL"
mkdir -p "$BORINGSSL_INSTALL/include" "$BORINGSSL_INSTALL/lib"
cp -R "$BORINGSSL_SOURCE/include/." "$BORINGSSL_INSTALL/include/"
cp "$BORINGSSL_BUILD/libcrypto.a" "$BORINGSSL_INSTALL/lib/"
cp "$BORINGSSL_BUILD/libssl.a" "$BORINGSSL_INSTALL/lib/"

CORE_BUILD="$WORK_DIR/aproxy-build"
cmake -S "$ROOT_DIR" -B "$CORE_BUILD" -GNinja \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DANDROID_ABI="$ABI" \
    -DANDROID_PLATFORM="android-$ANDROID_API" \
    -DANDROID_STL=c++_shared \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$OUTPUT_DIR" \
    -DAPROXY_BORINGSSL_ROOT="$BORINGSSL_INSTALL" \
    -DAPROXY_ENABLE_TUN=ON \
    -DAPROXY_FETCH_ANDROID_DEPS=ON \
    -DFETCHCONTENT_UPDATES_DISCONNECTED=ON
cmake --build "$CORE_BUILD" --target aproxy

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/include" "$OUTPUT_DIR/lib"
cp -R "$ROOT_DIR/include/." "$OUTPUT_DIR/include/"
cp -R "$CORE_BUILD/_deps/aproxy_libuv-src/include/." "$OUTPUT_DIR/include/"
cp "$CORE_BUILD/libcore.so" "$OUTPUT_DIR/lib/"
case "$STRIP_MODE" in
    strip|objcopy)
        "$STRIP_TOOL" --strip-unneeded "$OUTPUT_DIR/lib/libcore.so"
        ;;
esac

if [ "$ELF_INSPECTOR_MODE" = readobj ]; then
    alignment_ok=$(
        "$ELF_INSPECTOR" --program-headers "$OUTPUT_DIR/lib/libcore.so" | awk '
        $1 == "Type:" { load = ($2 == "PT_LOAD") }
        load && $1 == "Alignment:" {
            found = 1
            if (($2 + 0) < 16384) {
                invalid = 1
            }
            load = 0
        }
        END { print (found && !invalid) ? "yes" : "no" }
    '
    )
else
    alignment_ok=$(
        "$ELF_INSPECTOR" -lW "$OUTPUT_DIR/lib/libcore.so" | awk '
        $1 == "LOAD" {
            found = 1
            if ($NF != "0x4000" && $NF != "0x8000" &&
                $NF != "0x10000" && $NF != "0x20000" &&
                $NF != "0x40000" && $NF != "0x80000" &&
                $NF != "0x100000" && $NF != "0x200000") {
                invalid = 1
            }
        }
        END { print (found && !invalid) ? "yes" : "no" }
    '
    )
fi
if [ "$alignment_ok" != yes ]; then
    echo "libcore.so does not use at least 16 KiB PT_LOAD alignment" >&2
    exit 1
fi

echo "Solaris core Android artifacts: $OUTPUT_DIR"
