#!/usr/bin/env bash
#
# trace-ui 跨平台构建脚本
# 支持 Windows (MSYS/Git Bash), macOS, Linux
#
# 用法:
#   ./build.sh dev       # 开发模式（Vite HMR + Rust 热重载）
#   ./build.sh debug     # 构建 debug 版本
#   ./build.sh release   # 构建 release 版本（LTO 优化）
#   ./build.sh bundle    # 打包安装程序（.msi / .dmg / .deb）
#   ./build.sh clean     # 清理所有构建产物
#

set -euo pipefail

# ── 颜色输出 ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
title() { echo -e "\n${BOLD}═══ $* ═══${NC}"; }

# ── 项目根目录 ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

WEB_DIR="src-web"

# ── 平台检测 ──
detect_platform() {
    local uname_s
    uname_s="$(uname -s)"
    case "$uname_s" in
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            PLATFORM="windows"
            BINARY_EXT=".exe"
            BUNDLE_TYPE="msi"
            ;;
        Darwin)
            PLATFORM="macos"
            BINARY_EXT=""
            BUNDLE_TYPE="dmg"
            ;;
        Linux)
            PLATFORM="linux"
            BINARY_EXT=""
            BUNDLE_TYPE="deb"
            ;;
        *)
            err "不支持的平台: $uname_s"
            exit 1
            ;;
    esac
    info "平台: ${BOLD}$PLATFORM${NC} ($uname_s)"
}

# ── 依赖检查 ──
check_deps() {
    title "检查依赖"
    local missing=0

    if command -v node &>/dev/null; then
        ok "node $(node --version)"
    else
        err "未找到 node，请安装 Node.js"; missing=1
    fi

    if command -v npm &>/dev/null; then
        ok "npm $(npm --version)"
    else
        err "未找到 npm"; missing=1
    fi

    if command -v cargo &>/dev/null; then
        ok "cargo $(cargo --version | awk '{print $2}')"
    else
        err "未找到 cargo，请安装 Rust"; missing=1
    fi

    if command -v cargo-tauri &>/dev/null || cargo tauri --version &>/dev/null 2>&1; then
        ok "cargo-tauri $(cargo tauri --version 2>/dev/null | awk '{print $2}' || echo '已安装')"
    else
        warn "未找到 cargo-tauri，bundle 命令不可用（安装: cargo install tauri-cli）"
    fi

    if [[ $missing -ne 0 ]]; then
        err "缺少必要依赖，请先安装后重试"
        exit 1
    fi
}

# ── 前端构建 ──
build_frontend() {
    title "构建前端"
    cd "$SCRIPT_DIR/$WEB_DIR"

    if [[ ! -d node_modules ]]; then
        info "安装 npm 依赖..."
        npm install
    fi

    info "构建前端（tsc + vite）..."
    npm run build
    ok "前端构建完成 → $WEB_DIR/dist/"
    cd "$SCRIPT_DIR"
}

# ── Rust 构建 ──
build_rust() {
    local mode="$1"  # debug | release
    title "构建 Rust ($mode)"
    cd "$SCRIPT_DIR"

    if [[ "$mode" == "release" ]]; then
        cargo build --release --features custom-protocol
        local bin="target/release/trace-ui${BINARY_EXT}"
    else
        cargo build --features custom-protocol
        local bin="target/debug/trace-ui${BINARY_EXT}"
    fi

    if [[ -f "$bin" ]]; then
        local size
        size=$(du -h "$bin" | cut -f1)
        ok "Rust 构建完成 → $bin ($size)"
    else
        err "构建产物未找到: $bin"
        exit 1
    fi

    # macOS: 创建 .app Bundle 以避免启动时弹出终端
    if [[ "$PLATFORM" == "macos" ]]; then
        create_macos_app "$bin" "$mode"
    fi
}

# ── macOS .app Bundle 生成 ──
create_macos_app() {
    local bin="$1"
    local mode="$2"
    local app_name="Trace UI.app"
    local app_dir="target/$mode/$app_name"

    info "创建 macOS App Bundle..."
    mkdir -p "$app_dir/Contents/MacOS"
    mkdir -p "$app_dir/Contents/Resources"

    # 复制二进制文件
    cp -f "$bin" "$app_dir/Contents/MacOS/trace-ui"

    # 复制图标
    if [[ -f "icons/icon.icns" ]]; then
        cp -f "icons/icon.icns" "$app_dir/Contents/Resources/icon.icns"
    fi

    # 从 tauri.conf.json 读取版本号
    local app_version
    app_version=$(grep '"version"' tauri.conf.json | head -1 | sed 's/.*"\([0-9][0-9.]*\)".*/\1/')
    info "App version: $app_version"

    # 生成 Info.plist
    cat > "$app_dir/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>trace-ui</string>
    <key>CFBundleIdentifier</key>
    <string>com.ai-trace.trace-ui</string>
    <key>CFBundleName</key>
    <string>Trace UI</string>
    <key>CFBundleDisplayName</key>
    <string>Trace UI</string>
    <key>CFBundleVersion</key>
    <string>${app_version}</string>
    <key>CFBundleShortVersionString</key>
    <string>${app_version}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>icon</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.13</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

    # Ad-hoc 签名（ARM64 macOS 强制要求，否则内核直接 SIGKILL）
    info "签名 App Bundle (ad-hoc)..."
    codesign --force --deep --sign - "$app_dir"

    ok "App Bundle 创建完成 → $app_dir"
    info "启动方式: open \"$app_dir\""
}

# ── Tauri 打包 ──
build_bundle() {
    title "打包安装程序 ($BUNDLE_TYPE)"
    cd "$SCRIPT_DIR"

    if ! cargo tauri --version &>/dev/null 2>&1; then
        err "需要 cargo-tauri CLI（安装: cargo install tauri-cli）"
        exit 1
    fi

    cargo tauri build
    ok "打包完成，产物位于 target/release/bundle/"
    cd "$SCRIPT_DIR"
}

# ── 清理 ──
do_clean() {
    title "清理构建产物"

    info "清理 Rust 产物..."
    cargo clean

    if [[ -d "$WEB_DIR/dist" ]]; then
        info "清理前端产物..."
        rm -rf "$WEB_DIR/dist"
    fi

    if [[ -d "$WEB_DIR/node_modules" ]]; then
        read -rp "是否删除 node_modules？[y/N] " answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            rm -rf "$WEB_DIR/node_modules"
            ok "node_modules 已删除"
        fi
    fi

    ok "清理完成"
}

# ── 开发模式 ──
do_dev() {
    title "启动开发模式"
    cd "$SCRIPT_DIR"

    if [[ ! -d "$SCRIPT_DIR/$WEB_DIR/node_modules" ]]; then
        info "安装 npm 依赖..."
        cd "$SCRIPT_DIR/$WEB_DIR"
        npm install
        cd "$SCRIPT_DIR"
    fi

    info "启动 cargo tauri dev（Vite HMR + Rust 热重载）..."
    cargo tauri dev
}

# ── 主流程 ──
main() {
    local cmd="${1:-help}"
    local start_time
    start_time=$(date +%s)

    detect_platform

    case "$cmd" in
        dev)
            check_deps
            do_dev
            ;;
        debug)
            check_deps
            build_frontend
            build_rust debug
            ;;
        release)
            check_deps
            build_frontend
            build_rust release
            ;;
        bundle)
            check_deps
            build_frontend
            build_bundle
            ;;
        clean)
            do_clean
            ;;
        help|--help|-h)
            echo "用法: $0 <command>"
            echo ""
            echo "命令:"
            echo "  dev       开发模式（Vite HMR + Rust 热重载）"
            echo "  debug     构建 debug 版本"
            echo "  release   构建 release 版本（LTO 优化）"
            echo "  bundle    打包安装程序（.msi / .dmg / .deb）"
            echo "  clean     清理所有构建产物"
            exit 0
            ;;
        *)
            err "未知命令: $cmd"
            echo "运行 $0 help 查看可用命令"
            exit 1
            ;;
    esac

    local end_time elapsed
    end_time=$(date +%s)
    elapsed=$((end_time - start_time))
    echo ""
    ok "完成！耗时 ${elapsed}s"
}

main "$@"
