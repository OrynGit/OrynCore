#!/usr/bin/env bash
# 构建 OrynCore.xcframework（iOS 真机 arm64 + 模拟器 arm64 + macOS arm64/x86_64 通用库）。
#
# 用法：build/build-xcframework.sh [debug|release]
# 产物：ORYN_XCFRAMEWORK_OUT 指定的路径；未指定时，存在同级 Oryn 仓库则写到
# ../Oryn/Frameworks/OrynCore.xcframework（App 工程引用的位置），否则写到 target/OrynCore.xcframework。
# 默认 feature 已包含全部协议（Hysteria2 / TUIC / WireGuard 等），发布构建即完整构建。
# 开发时可设置 ORYN_CARGO_FEATURES 追加 feature；ORYN_PLATFORMS=ios 或 macos 只构建一个平台；
# ORYN_IOS_DEVICE_ONLY=1 与 ORYN_PLATFORMS=ios 合用时跳过模拟器切片。
set -euo pipefail

PROFILE="${1:-release}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -n "${ORYN_XCFRAMEWORK_OUT:-}" ]]; then
  OUT="$ORYN_XCFRAMEWORK_OUT"
elif [[ -d "$ROOT/../Oryn" ]]; then
  OUT="$(cd "$ROOT/../Oryn" && pwd)/Frameworks/OrynCore.xcframework"
else
  OUT="$ROOT/target/OrynCore.xcframework"
fi
PLATFORMS="${ORYN_PLATFORMS:-ios macos}"
TARGETS=()
if [[ "$PLATFORMS" == *ios* ]]; then
  TARGETS+=(aarch64-apple-ios)
  # ORYN_IOS_DEVICE_ONLY=1：只构建真机切片（真机迭代调试省时间与磁盘，产物不能用于模拟器）
  [[ -z "${ORYN_IOS_DEVICE_ONLY:-}" ]] && TARGETS+=(aarch64-apple-ios-sim)
fi
[[ "$PLATFORMS" == *macos* ]] && TARGETS+=(aarch64-apple-darwin x86_64-apple-darwin)

# 使用 rustup 的工具链（读取 rust-toolchain.toml，含 iOS / macOS 目标）。
# 若 PATH 中 Homebrew 的 rustc 排在前面，cargo 会用它编译而找不到 iOS 标准库。
export PATH="$HOME/.cargo/bin:$PATH"
CARGO="${CARGO:-cargo}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

export IPHONEOS_DEPLOYMENT_TARGET=16.0
export MACOSX_DEPLOYMENT_TARGET=13.0

cd "$ROOT"
flags=(-p oryn-ffi)
[[ "$PROFILE" == "release" ]] && flags+=(--release)
if [[ -n "${ORYN_CARGO_FEATURES:-}" ]]; then
  flags+=(--features "$ORYN_CARGO_FEATURES")
fi

for t in "${TARGETS[@]}"; do
  echo "==> cargo build ($PROFILE) --target $t"
  # rquickjs-sys 的绑定由 bindgen 生成，使用对应平台的 SDK 头文件。
  case "$t" in
    *-ios-sim) oryn_bindgen_sdk=iphonesimulator ;;
    *-ios) oryn_bindgen_sdk=iphoneos ;;
    *) oryn_bindgen_sdk=macosx ;;
  esac
  BINDGEN_EXTRA_CLANG_ARGS="-isysroot $(xcrun --sdk "$oryn_bindgen_sdk" --show-sdk-path)" \
  "$CARGO" build "${flags[@]}" --target "$t"
done

HEADERS="$(mktemp -d)"
UNIVERSAL="$(mktemp -d)"
trap 'rm -rf "$HEADERS" "$UNIVERSAL"' EXIT
cp "$ROOT/crates/oryn-ffi/include/"* "$HEADERS/"

rm -rf "$OUT"
mkdir -p "$(dirname "$OUT")"
args=()
for t in "${TARGETS[@]}"; do
  [[ "$t" == *-darwin ]] && continue
  args+=(-library "$TARGET_DIR/$t/$PROFILE/liboryncore.a" -headers "$HEADERS")
done
if [[ "$PLATFORMS" == *macos* ]]; then
  # 同一平台在 xcframework 里只能有一个切片，两种架构先合成通用静态库。
  lipo -create \
    "$TARGET_DIR/aarch64-apple-darwin/$PROFILE/liboryncore.a" \
    "$TARGET_DIR/x86_64-apple-darwin/$PROFILE/liboryncore.a" \
    -output "$UNIVERSAL/liboryncore.a"
  args+=(-library "$UNIVERSAL/liboryncore.a" -headers "$HEADERS")
fi
xcodebuild -create-xcframework "${args[@]}" -output "$OUT" >/dev/null
echo "==> $OUT"
