# 📦 Releases

Pre-compiled binaries for MedoVPN Bridge will be available here.

## Download

Visit the [Releases page](https://github.com/YOUR_USERNAME/MedoVPN-Bridge/releases) to download:

- **Windows**: `medovpn-bridge-windows-amd64.exe`
- **Linux**: `medovpn-bridge-linux-amd64`
- **Debian/Ubuntu**: `medovpn-bridge_amd64.deb`

## Build from Source

```bash
cd client
go build -o medovpn-bridge medovpn-bridge.go
```

## Verify Downloads

All releases are signed with GPG. Import the public key and verify:

```bash
# Import public key
gpg --import public-key.asc

# Verify signature
gpg --verify medovpn-bridge-linux-amd64.sig medovpn-bridge-linux-amd64
```
