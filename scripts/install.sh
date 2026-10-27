#!/usr/bin/env bash
#
# veilnet installer - auto-detects OS and installs dependencies
# Usage: curl -sL https://raw.githubusercontent.com/animesao/veilnet/main/scripts/install.sh | sudo bash
#
set -euo pipefail

VEILNET_VERSION="0.1.0"
VEILNET_REPO="animesao/veilnet"
VEILNET_INSTALL_DIR="/opt/veilnet"
VEILNET_CONFIG_DIR="/etc/veilnet"
VEILNET_BIN_DIR="/usr/local/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="$ID"
        OS_ID_LIKE="$ID_LIKE"
        OS_NAME="$NAME"
        OS_VERSION="$VERSION_ID"
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    
    log_info "Detected: $OS_NAME ($OS_VERSION)"
    
    # Determine family
    if [[ "$OS_ID" == "arch" ]] || [[ "$OS_ID_LIKE" == *"arch"* ]]; then
        OS_FAMILY="arch"
    elif [[ "$OS_ID" == "debian" ]] || [[ "$OS_ID" == "ubuntu" ]] || [[ "$OS_ID_LIKE" == *"debian"* ]]; then
        OS_FAMILY="debian"
    elif [[ "$OS_ID" == "fedora" ]] || [[ "$OS_ID" == "rhel" ]] || [[ "$OS_ID" == "centos" ]] || [[ "$OS_ID_LIKE" == *"rhel"* ]]; then
        OS_FAMILY="rhel"
    elif [[ "$OS_ID" == "opensuse" ]] || [[ "$OS_ID" == "sles" ]]; then
        OS_FAMILY="suse"
    else
        OS_FAMILY="unknown"
    fi
    
    log_info "OS family: $OS_FAMILY"
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check kernel version
check_kernel() {
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1)
    local kernel_min=5
    
    if [[ $kernel_version -lt $kernel_min ]]; then
        log_error "Kernel $kernel_version is too old. Need >= 5.8"
        exit 1
    fi
    
    # Check BTF
    if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
        log_warn "BTF not found. veilnet may not work properly."
        log_warn "Try: sudo sysctl kernel.bpf_stats_enabled=1"
    else
        log_info "BTF available"
    fi
    
    # Check clsact
    if ! ip link help 2>&1 | grep -q clsact; then
        log_warn "TC clsact support may be limited"
    fi
}

# Install dependencies
install_deps() {
    log_info "Installing dependencies for $OS_FAMILY..."
    
    case "$OS_FAMILY" in
        arch)
            pacman -Sy --noconfirm \
                base-devel \
                clang \
                llvm \
                libelf \
                iproute2 \
                systemd \
                rustup \
                curl \
                wget
            ;;
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y \
                build-essential \
                clang \
                llvm \
                libelf-dev \
                libbpf-dev \
                iproute2 \
                systemd \
                rustup \
                curl \
                wget \
                pkg-config
            ;;
        rhel)
            dnf install -y \
                clang \
                llvm \
                libelf-devel \
                iproute2 \
                systemd \
                rustup-init \
                curl \
                wget \
                pkgconfig
            ;;
        suse)
            zypper install -y \
                clang \
                llvm-devel \
                libelf-devel \
                iproute2 \
                systemd \
                rust \
                curl \
                wget
            ;;
        *)
            log_error "Unsupported OS: $OS_ID"
            log_info "Please install manually: clang, llvm, libelf, iproute2, systemd, rust"
            ;;
    esac
    
    # Check if rustup exists
    if command -v rustup &> /dev/null; then
        log_info "Rust toolchain found"
    else
        log_warn "Rust not found, will try to install binary release"
    fi
}

# Download or build veilnet
install_veilnet() {
    log_info "Installing veilnet $VEILNET_VERSION..."
    
    # Create directories
    mkdir -p "$VEILNET_INSTALL_DIR"
    mkdir -p "$VEILNET_CONFIG_DIR"
    mkdir -p "$VEILNET_BIN_DIR"
    
    # Try to download pre-built release
    local arch
    arch=$(uname -m)
    local download_url="https://github.com/$VEILNET_REPO/releases/latest/download/veilnetd"
    
    if command -v curl &> /dev/null; then
        if curl -sL --fail "$download_url" -o "$VEILNET_INSTALL_DIR/veilnetd"; then
            chmod +x "$VEILNET_INSTALL_DIR/veilnetd"
            ln -sf "$VEILNET_INSTALL_DIR/veilnetd" "$VEILNET_BIN_DIR/veilnetd"
            log_info "Downloaded veilnetd"
        else
            log_warn "Could not download pre-built binary, will build from source"
            build_from_source
        fi
    else
        build_from_source
    fi
    
    # Install veilctl (CLI)
    local cli_url="https://github.com/$VEILNET_REPO/releases/latest/download/veilctl"
    if command -v curl &> /dev/null; then
        if curl -sL --fail "$cli_url" -o "$VEILNET_INSTALL_DIR/veilctl"; then
            chmod +x "$VEILNET_INSTALL_DIR/veilctl"
            ln -sf "$VEILNET_INSTALL_DIR/veilctl" "$VEILNET_BIN_DIR/veilctl"
            log_info "Downloaded veilctl"
        fi
    fi
    
    # Install config
    if [[ ! -f "$VEILNET_CONFIG_DIR/veilnet.toml" ]]; then
        cat > "$VEILNET_CONFIG_DIR/veilnet.toml" << 'EOF'
[interface]
name = "eth0"

[[rule]]
cidr = "0.0.0.0/0"
strategy = "multisplit"
EOF
        log_info "Created config at $VEILNET_CONFIG_DIR/veilnet.toml"
    fi
    
    # Install systemd service
    if command -v systemctl &> /dev/null; then
        cat > /etc/systemd/system/veilnet.service << 'EOF'
[Unit]
Description=veilnet - TC + eBPF DPI bypass
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/veilnetd
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        log_info "Installed systemd service"
    fi
}

# Build from source
build_from_source() {
    log_info "Building from source..."
    
    # Check for required tools
    local missing=()
    for cmd in cargo clang llvm-strip; do
        if ! command -v $cmd &> /dev/null; then
            missing+=($cmd)
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing tools: ${missing[*]}"
        log_error "Install them and try again, or use pre-built release"
        return 1
    fi
    
    # Clone and build
    local temp_dir
    temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    git clone --depth 1 "https://github.com/$VEILNET_REPO.git" .
    
    cargo build --release -p veilnetd -p veilctl
    
    # Install binaries
    cp target/release/veilnetd "$VEILNET_INSTALL_DIR/"
    cp target/release/veilctl "$VEILNET_INSTALL_DIR/"
    chmod +x "$VEILNET_INSTALL_DIR"/*
    
    ln -sf "$VEILNET_INSTALL_DIR/veilnetd" "$VEILNET_BIN_DIR/veilnetd"
    ln -sf "$VEILNET_INSTALL_DIR/veilctl" "$VEILNET_BIN_DIR/veilctl"
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
    
    log_info "Built and installed from source"
}

# Enable and start service
enable_service() {
    if command -v systemctl &> /dev/null; then
        log_info "Enabling veilnet service..."
        systemctl enable veilnet.service || true
        systemctl start veilnet.service || true
        
        sleep 2
        if systemctl is-active --quiet veilnet; then
            log_info "veilnet is running!"
        else
            log_warn "veilnet failed to start. Check: systemctl status veilnet"
        fi
    fi
}

# Print status
print_status() {
    echo ""
    echo "========================================"
    echo "  veilnet $VEILNET_VERSION installed"
    echo "========================================"
    echo ""
    echo "Config: $VEILNET_CONFIG_DIR/veilnet.toml"
    echo "Binary: $VEILNET_BIN_DIR/veilnetd"
    echo ""
    echo "Commands:"
    echo "  veilctl strategies     # List strategies"
    echo "  veilctl status         # Check status"
    echo "  sudo systemctl start veilnet    # Start"
    echo "  sudo systemctl stop veilnet     # Stop"
    echo "  sudo systemctl restart veilnet  # Restart"
    echo ""
}

# Main
main() {
    echo "========================================"
    echo "  veilnet Installer"
    echo "  Version: $VEILNET_VERSION"
    echo "========================================"
    echo ""
    
    check_root
    detect_os
    check_kernel
    install_deps
    install_veilnet
    enable_service
    print_status
}

# Run
main "$@"