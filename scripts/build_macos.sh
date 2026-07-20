#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT_DIR=${1:-"$ROOT_DIR/build-macos/core.xcframework"}
WORK_DIR=${SOLARIS_CORE_MACOS_WORK_DIR:-"$ROOT_DIR/build-macos/work"}
DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-13.0}
GENERATOR=${CMAKE_GENERATOR:-Ninja}
BORINGSSL_REPOSITORY=${BORINGSSL_REPOSITORY:-https://boringssl.googlesource.com/boringssl}
BORINGSSL_COMMIT=922c15f36cc75db5af33c46f9ea8934553fb808e

if ! command -v xcrun >/dev/null 2>&1 ||
   ! command -v xcodebuild >/dev/null 2>&1; then
    echo "build_macos.sh must run on macOS with Xcode command-line tools" >&2
    exit 1
fi
case "$OUTPUT_DIR" in
    ""|/) echo "Refusing unsafe macOS output directory: $OUTPUT_DIR" >&2; exit 1 ;;
esac

SDK_PATH=$(xcrun --sdk macosx --show-sdk-path)
mkdir -p "$WORK_DIR"
BORINGSSL_SOURCE="$WORK_DIR/boringssl-src"
if [ ! -d "$BORINGSSL_SOURCE/.git" ]; then
    mkdir -p "$BORINGSSL_SOURCE"
    git -C "$BORINGSSL_SOURCE" init
    git -C "$BORINGSSL_SOURCE" remote add origin "$BORINGSSL_REPOSITORY"
fi
git -C "$BORINGSSL_SOURCE" fetch --depth 1 origin "$BORINGSSL_COMMIT"
if [ "$(git -C "$BORINGSSL_SOURCE" rev-parse HEAD 2>/dev/null || true)" != \
     "$BORINGSSL_COMMIT" ] ||
   ! git -C "$BORINGSSL_SOURCE" apply --reverse --check \
       "$ROOT_DIR/third_party/boringssl-reality.patch" 2>/dev/null; then
    git -C "$BORINGSSL_SOURCE" checkout --detach "$BORINGSSL_COMMIT"
    git -C "$BORINGSSL_SOURCE" reset --hard "$BORINGSSL_COMMIT"
    git -C "$BORINGSSL_SOURCE" clean -fd
    git -C "$BORINGSSL_SOURCE" apply \
        "$ROOT_DIR/third_party/boringssl-reality.patch"
fi

build_slice()
{
    ARCH=$1
    SLICE_DIR="$WORK_DIR/macos-$ARCH"
    BORINGSSL_BUILD="$SLICE_DIR/boringssl-build"
    BORINGSSL_INSTALL="$SLICE_DIR/boringssl-install"
    CORE_BUILD="$SLICE_DIR/aproxy-build"
    CORE_INSTALL="$SLICE_DIR/install"

    cmake -S "$BORINGSSL_SOURCE" -B "$BORINGSSL_BUILD" -G "$GENERATOR" \
        -DCMAKE_SYSTEM_NAME=Darwin \
        -DCMAKE_OSX_SYSROOT="$SDK_PATH" \
        -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET="$DEPLOYMENT_TARGET" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DBUILD_SHARED_LIBS=OFF
    cmake --build "$BORINGSSL_BUILD" --target crypto ssl

    rm -rf "$BORINGSSL_INSTALL"
    mkdir -p "$BORINGSSL_INSTALL/include" "$BORINGSSL_INSTALL/lib"
    cp -R "$BORINGSSL_SOURCE/include/." "$BORINGSSL_INSTALL/include/"
    cp "$BORINGSSL_BUILD/libcrypto.a" "$BORINGSSL_INSTALL/lib/"
    cp "$BORINGSSL_BUILD/libssl.a" "$BORINGSSL_INSTALL/lib/"

    cmake -S "$ROOT_DIR" -B "$CORE_BUILD" -G "$GENERATOR" \
        -DCMAKE_SYSTEM_NAME=Darwin \
        -DCMAKE_OSX_SYSROOT="$SDK_PATH" \
        -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET="$DEPLOYMENT_TARGET" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$CORE_INSTALL" \
        -DAPROXY_BORINGSSL_ROOT="$BORINGSSL_INSTALL" \
        -DAPROXY_ENABLE_TUN=ON \
        -DAPROXY_FETCH_APPLE_DEPS=ON
    cmake --build "$CORE_BUILD" --target aproxy_ios_archive
    cmake --install "$CORE_BUILD"
}

build_slice arm64
build_slice x86_64

UNIVERSAL_DIR="$WORK_DIR/macos-universal"
UNIVERSAL_LIBRARY="$UNIVERSAL_DIR/lib/libcore.a"
mkdir -p "$UNIVERSAL_DIR/include" "$UNIVERSAL_DIR/lib"
cp -R "$WORK_DIR/macos-arm64/install/include/." "$UNIVERSAL_DIR/include/"
rm -f "$UNIVERSAL_LIBRARY"
xcrun lipo -create \
    "$WORK_DIR/macos-arm64/install/lib/libcore.a" \
    "$WORK_DIR/macos-x86_64/install/lib/libcore.a" \
    -output "$UNIVERSAL_LIBRARY"

rm -rf "$OUTPUT_DIR"
xcodebuild -create-xcframework \
    -library "$UNIVERSAL_LIBRARY" \
    -headers "$UNIVERSAL_DIR/include" \
    -output "$OUTPUT_DIR"

echo "Solaris core macOS XCFramework: $OUTPUT_DIR"
