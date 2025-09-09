# cmon-proxy Debugging Guide

This guide provides comprehensive instructions for live debugging of the cmon-proxy application.

## 🚀 Quick Start

### Prerequisites
1. **Go 1.23+** installed - check with `go version`
2. **VS Code** with Go extension (recommended) - check with `code --list-extensions | grep golang.go`

### Method 1: Using VS Code (Recommended)

1. Open the project in VS Code
2. Go to the Debug panel (Ctrl+Shift+D)
3. Select "Debug cmon-proxy" (uses local ccmgr.yaml)
4. Press F5 to start debugging

### Method 2: Using Command Line

```bash
# Build with debug symbols
go build -gcflags="all=-N -l" -o ccmgr-debug .

# Run in debug mode
GIN_MODE=debug DEBUG_WEB_RPC=true ./ccmgr-debug --basedir .
```




## Debugging Configuration

### VS Code Configuration

The project includes pre-configured VS Code debug configurations:

- **Debug cmon-proxy**: Direct debugging with local ccmgr.yaml file
- **Attach to cmon-proxy**: Attach to a running debug session (for remote debugging)

### Environment Variables

Set these environment variables for enhanced debugging:

```bash
export GIN_MODE=debug          # Enable Gin debug mode
export DEBUG_WEB_RPC=true      # Enable WebRPC debugging
export LOG_LEVEL=debug         # Set log level to debug
```

### Configuration File

Create or modify `ccmgr.yaml` for your debugging needs:

```yaml
# Example debug configuration (ccmgr.yaml)
filename: ccmgr.yaml
webapproot: /var/www
fetch_jobs_hours: 12
fetch_backups_days: 9
instances:
    - xid: your-instance-id
      url: your-cmon-url/api
      name: your-instance-name
      controller_id: your-controller-id
port: 19052  # Debug port
logfile: ccmgr.log
users:
    - username: root
      passwordhash: your-password-hash
# Add your specific configuration here
```

## Debugging Features

### Breakpoints

Set breakpoints in VS Code by clicking on the line number or pressing F9.

### 🎯 Common Breakpoint Locations

1. **Main entry point**: `main.go:main()`
2. **HTTP request handling**: `rpcserver/server.go:Start()`
3. **Router handling**: `multi/router/router.go`
4. **Authentication**: `auth/auth.go`
5. **Configuration loading**: `config/config.go`

### 📍 Key Debug Ports
- **Debug Port**: 2345 (VS Code debugger)
- **HTTP Port**: 19052 (Application - from ccmgr.yaml)

### Debug Console Commands

When debugging in VS Code, you can use the debug console and standard debugging features:

- Set breakpoints by clicking on line numbers
- Use the debug toolbar to continue, step over, step into, step out
- View variables in the Variables panel
- Use the Debug Console to evaluate expressions
- View call stack in the Call Stack panel

## Troubleshooting

### Common Issues

1. **Port already in use**:
   ```bash
   # Check what's using the port
   lsof -i :2345
   lsof -i :19051
   
   # Kill the process
   kill -9 <PID>
   ```

2. **Debug symbols not found**:
   ```bash
   # Rebuild with debug symbols
   go build -gcflags="all=-N -l" -o ccmgr-debug .
   ```


### Debug Logs

Enable debug logging by setting environment variables:

```bash
export GIN_MODE=debug
export DEBUG_WEB_RPC=true
export LOG_LEVEL=debug
```

### Performance Debugging

For performance issues, use Go's built-in profiling:

```bash
# CPU profiling
go tool pprof http://localhost:19052/debug/pprof/profile

# Memory profiling
go tool pprof http://localhost:19052/debug/pprof/heap

# Goroutine profiling
go tool pprof http://localhost:19052/debug/pprof/goroutine
```

## Advanced Debugging

### Remote Debugging

To debug a remote instance:

1. Use VS Code's remote debugging capabilities
2. Connect from VS Code using "Attach to cmon-proxy" configuration

### Debugging Tests

1. In VS Code, use the "Go: Test Function At Cursor" command
2. Set breakpoints in test files and run tests in debug mode
3. Use the Test Explorer to run and debug specific tests

### Memory Debugging

```bash
# Run with memory profiling
go build -gcflags="all=-N -l" -o ccmgr-debug .
GODEBUG=gctrace=1 ./ccmgr-debug
```

## Integration with IDEs

### VS Code

The project includes `.vscode/launch.json` with pre-configured debug configurations.

### GoLand

1. Go to Run → Edit Configurations
2. Add new Go Remote configuration
3. Set host to `localhost` and port to `2345`

### Vim/Neovim

Configure DAP (Debug Adapter Protocol) clients for Go debugging.

## Security Considerations

⚠️ **Important**: Debug mode should only be used in development environments.

- Debug ports (2345) should not be exposed to production
- Debug symbols increase binary size
- Debug mode may expose sensitive information in logs

## Support

For issues with debugging setup:

1. Check the troubleshooting section above
2. Review the application logs
3. Verify Go version compatibility
4. Check firewall and network configurations

## Additional Resources

- [Go Debugging Guide](https://golang.org/doc/gdb)
- [VS Code Go Extension](https://marketplace.visualstudio.com/items?itemName=golang.Go) 