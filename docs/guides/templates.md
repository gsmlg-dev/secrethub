# SecretHub Templates Guide

## Overview

SecretHub Templates allow you to render secrets into configuration files with dynamic variable substitution, conditional logic, and automatic application reloading. Templates use EEx (Embedded Elixir) syntax, similar to ERB, Jinja2, and Go templates.

## Table of Contents

- [Basic Concepts](#basic-concepts)
- [Template Syntax](#template-syntax)
- [Variable Bindings](#variable-bindings)
- [Sinks](#sinks)
- [Use Cases](#use-cases)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Basic Concepts

### Templates

A **template** defines how secrets should be rendered into configuration files. Templates contain:
- **Template Content**: The template string with EEx syntax
- **Variable Bindings**: Mapping of template variables to secret paths
- **Status**: active, inactive, or archived

### Sinks

A **sink** defines where a rendered template is written. Sinks contain:
- **File Path**: Target location for the rendered content
- **Permissions**: File permissions (mode, owner, group)
- **Backup**: Whether to create backups before writing
- **Reload Trigger**: How to reload the application after writing

### Workflow

1. **Create Template**: Define template content and variable bindings
2. **Configure Sinks**: Specify where templates should be written
3. **Agent Renders**: Agent fetches secrets and renders templates
4. **Atomic Write**: Content is written atomically to sinks
5. **Application Reload**: Application is triggered to reload configuration

## Template Syntax

SecretHub uses **EEx (Embedded Elixir)** syntax for templates.

### Variable Substitution

```elixir
# Basic variable output
<%= variable_name %>

# Nested access
<%= secret.password %>
<%= config.database.host %>

# With default value
<%= api_key || "default-key" %>
```

### Conditional Rendering

```elixir
# If statement
<%= if enable_feature do %>
feature_enabled=true
<% else %>
feature_enabled=false
<% end %>

# Unless statement
<%= unless disabled do %>
service=running
<% end %>

# Inline conditional
<%= if env == "production", do: "prod", else: "dev" %>
```

### Loops and Iteration

```elixir
# Iterate over list
<%= for server <- servers do %>
server=<%= server.host %>:<%= server.port %>
<% end %>

# With index
<%= for {item, index} <- Enum.with_index(items) do %>
item_<%= index %>=<%= item %>
<% end %>

# Filter while iterating
<%= for server <- servers, server.active do %>
active_server=<%= server.name %>
<% end %>
```

### Helper Functions

SecretHub provides built-in helper functions:

```elixir
# String manipulation
<%= upcase(username) %>          # ADMIN
<%= downcase(service_name) %>    # myservice

# Encoding
<%= base64_encode(secret) %>     # Base64 encoded
<%= base64_decode(encoded) %>    # Decoded value
<%= json_encode(data) %>         # JSON string

# List operations
<%= join(["a", "b", "c"], ",") %> # "a,b,c"
```

### Comments

```elixir
<%# This is a comment and won't appear in output %>
```

## Variable Bindings

Variable bindings map template variable names to secret paths in SecretHub.

### Basic Binding

```json
{
  "db_password": "prod.database.password",
  "api_key": "prod.api.key",
  "jwt_secret": "prod.auth.jwt_secret"
}
```

Template usage:
```elixir
DB_PASSWORD=<%= db_password %>
API_KEY=<%= api_key %>
JWT_SECRET=<%= jwt_secret %>
```

### Nested Secrets

For secrets with multiple fields, bind to the secret path and access fields:

```json
{
  "database": "prod.database"
}
```

Template usage:
```elixir
DB_HOST=<%= database.host %>
DB_PORT=<%= database.port %>
DB_USER=<%= database.username %>
DB_PASS=<%= database.password %>
```

### Complex Data Structures

```json
{
  "servers": "prod.load_balancer.servers"
}
```

Template usage:
```elixir
<%= for server <- servers do %>
upstream <%= server.name %> {
  server <%= server.host %>:<%= server.port %>;
}
<% end %>
```

## Sinks

Sinks define how and where rendered templates are written.

### Basic Sink Configuration

```json
{
  "name": "app-config",
  "file_path": "/etc/myapp/config.conf",
  "permissions": {
    "mode": 384,
    "owner": "myapp",
    "group": "myapp"
  },
  "backup_enabled": true,
  "reload_trigger": {
    "type": "signal",
    "value": "HUP",
    "target": "myapp"
  }
}
```

### File Permissions

**Mode**: Decimal representation of octal permissions
- `384` = `0o600` = rw-------
- `420` = `0o644` = rw-r--r--
- `493` = `0o755` = rwxr-xr-x

**Owner/Group**: System username or group name

### Reload Triggers

#### Signal-based Reload

Send a signal to a process:

```json
{
  "type": "signal",
  "value": "HUP",
  "target": "nginx"
}
```

Common signals:
- `HUP`: Reload configuration
- `USR1`: Custom reload
- `USR2`: Custom reload

#### HTTP-based Reload

Call an HTTP endpoint:

```json
{
  "type": "http",
  "value": "http://localhost:8080/reload",
  "target": null
}
```

#### Script-based Reload

Execute a custom script:

```json
{
  "type": "script",
  "value": "/usr/local/bin/reload-app.sh",
  "target": null
}
```

### Atomic Writes

All sinks use atomic write-then-rename to ensure applications never see partial or corrupt files:

1. Write content to `.tmp` file
2. Set permissions on temporary file
3. Rename temporary file to final path (atomic operation)
4. Trigger reload if configured

### Backup

When `backup_enabled: true`, the existing file is copied to `.bak` before writing:

```
/etc/myapp/config.conf      # Current file
/etc/myapp/config.conf.bak  # Backup
/etc/myapp/config.conf.tmp  # Temporary (during write)
```

## Use Cases

### Use Case 1: Database Configuration

**Template Content:**
```elixir
[database]
host = <%= db.host %>
port = <%= db.port %>
username = <%= db.username %>
password = <%= db.password %>
database = <%= db.database %>
ssl_mode = <%= if db.ssl then "require" else "disable" end %>
max_connections = <%= db.max_connections || 100 %>
```

**Variable Bindings:**
```json
{
  "db": "prod.postgresql.primary"
}
```

**Sink Configuration:**
```json
{
  "name": "database-config",
  "file_path": "/etc/myapp/database.conf",
  "permissions": {"mode": 384, "owner": "myapp"},
  "backup_enabled": true,
  "reload_trigger": {
    "type": "signal",
    "value": "HUP",
    "target": "myapp"
  }
}
```

### Use Case 2: Environment Variables

**Template Content:**
```bash
#!/bin/bash
export DATABASE_URL="postgresql://<%= db.username %>:<%= db.password %>@<%= db.host %>:<%= db.port %>/<%= db.database %>"
export REDIS_URL="redis://<%= redis.host %>:<%= redis.port %>"
export API_KEY="<%= api_key %>"
export JWT_SECRET="<%= jwt_secret %>"
export ENVIRONMENT="<%= environment %>"
```

**Variable Bindings:**
```json
{
  "db": "prod.database",
  "redis": "prod.redis",
  "api_key": "prod.api.key",
  "jwt_secret": "prod.auth.jwt_secret",
  "environment": "prod.environment"
}
```

**Sink Configuration:**
```json
{
  "name": "env-file",
  "file_path": "/etc/myapp/env.sh",
  "permissions": {"mode": 384, "owner": "myapp"},
  "backup_enabled": true,
  "reload_trigger": {
    "type": "script",
    "value": "systemctl restart myapp"
  }
}
```

### Use Case 3: NGINX Configuration

**Template Content:**
```nginx
upstream backend {
  <%= for server <- backend_servers do %>
  server <%= server.host %>:<%= server.port %> weight=<%= server.weight || 1 %>;
  <% end %>
}

server {
  listen 443 ssl;
  server_name <%= domain %>;

  ssl_certificate /etc/ssl/<%= domain %>.crt;
  ssl_certificate_key /etc/ssl/<%= domain %>.key;

  <%= if basic_auth_enabled do %>
  auth_basic "Restricted";
  auth_basic_user_file /etc/nginx/.htpasswd;
  <% end %>

  location / {
    proxy_pass http://backend;
    proxy_set_header X-Api-Key "<%= api_key %>";
  }
}
```

**Variable Bindings:**
```json
{
  "backend_servers": "prod.backend.servers",
  "domain": "prod.domain",
  "basic_auth_enabled": "prod.nginx.basic_auth",
  "api_key": "prod.api.key"
}
```

**Sink Configuration:**
```json
{
  "name": "nginx-conf",
  "file_path": "/etc/nginx/conf.d/myapp.conf",
  "permissions": {"mode": 420, "owner": "root", "group": "root"},
  "backup_enabled": true,
  "reload_trigger": {
    "type": "signal",
    "value": "HUP",
    "target": "nginx"
  }
}
```

### Use Case 4: JSON Configuration

**Template Content:**
```json
{
  "database": {
    "host": "<%= db.host %>",
    "port": <%= db.port %>,
    "username": "<%= db.username %>",
    "password": "<%= db.password %>"
  },
  "redis": {
    "host": "<%= redis.host %>",
    "port": <%= redis.port %>
  },
  "features": {
    <%= for {feature, enabled} <- Enum.with_index(features) do %>
    "<%= feature.name %>": <%= feature.enabled %><%= if enabled < length(features) - 1, do: "," %>
    <% end %>
  }
}
```

## Best Practices

### 1. Use Descriptive Variable Names

**Good:**
```json
{
  "database_password": "prod.db.password",
  "api_key": "prod.api.key"
}
```

**Bad:**
```json
{
  "pwd": "prod.db.password",
  "key": "prod.api.key"
}
```

### 2. Group Related Secrets

**Good:**
```json
{
  "database": "prod.database"
}
```
```elixir
<%= database.host %>
<%= database.password %>
```

**Bad:**
```json
{
  "db_host": "prod.database.host",
  "db_password": "prod.database.password"
}
```

### 3. Use Defaults for Optional Values

```elixir
# Provide sensible defaults
port = <%= port || 5432 %>
timeout = <%= timeout || 30 %>
```

### 4. Validate Template Syntax

Always validate templates before deploying:
- Use the preview functionality in the UI
- Test with mock data
- Check for syntax errors

### 5. Enable Backups for Production

```json
{
  "backup_enabled": true
}
```

This allows rollback if rendering fails.

### 6. Use Appropriate File Permissions

- **Secrets (passwords, keys)**: `mode: 384` (0o600) - owner read/write only
- **Public configs**: `mode: 420` (0o644) - owner write, all read
- **Executables**: `mode: 493` (0o755) - owner all, others read/execute

### 7. Test Reload Triggers

Before production:
- Test signal-based reloads with your application
- Verify HTTP endpoints respond correctly
- Test scripts in staging environment

## Troubleshooting

### Template Syntax Errors

**Error:** `Compilation error: unexpected token`

**Cause:** Invalid EEx syntax

**Solution:**
- Check for unclosed tags: `<%= ... %>`
- Ensure proper nesting of conditionals and loops
- Use `<%# comment %>` for comments, not `<!-- -->`

### Missing Variables

**Error:** `Render error: undefined variable`

**Cause:** Variable used in template but not in bindings

**Solution:**
- Add variable to bindings: `{"var": "secret.path"}`
- Or use default: `<%= var || "default" %>`

### Secret Not Found

**Error:** `Missing secret: prod.db.password`

**Cause:** Secret path doesn't exist in SecretHub

**Solution:**
- Check secret path is correct
- Verify secret exists in SecretHub
- Check agent has access to secret (policies)

### Permission Denied

**Error:** `chown failed: Operation not permitted`

**Cause:** Agent doesn't have permission to change file ownership

**Solution:**
- Run agent as root (not recommended)
- Or remove `owner`/`group` from permissions
- Or use sudo in reload script

### Reload Failed

**Error:** `Signal failed: No such process`

**Cause:** Target process not running or wrong process name

**Solution:**
- Verify process is running: `ps aux | grep <target>`
- Check process name matches exactly
- Use `pkill -0 <target>` to test

### File Already Exists

**Error:** `rename failed: File exists`

**Cause:** Stale `.tmp` file from previous failed write

**Solution:**
- Manually remove `.tmp` file
- Check disk space is available
- Verify directory permissions

### Template Preview Not Working

**Cause:** Mock data format incorrect

**Solution:**
- Use valid JSON for mock data
- Match structure expected by template
- Example:
```json
{
  "database": {
    "host": "localhost",
    "password": "test123"
  }
}
```

### Common Pitfalls

1. **Using `&&` instead of `and`**
   ```elixir
   # Wrong
   <%= if x && y do %>

   # Correct
   <%= if x and y do %>
   ```

2. **Forgetting to close tags**
   ```elixir
   # Wrong - missing 'end'
   <%= if condition do %>
   content

   # Correct
   <%= if condition do %>
   content
   <% end %>
   ```

3. **Using quotes incorrectly in JSON**
   ```elixir
   # Wrong in JSON output
   "password": <%= password %>

   # Correct
   "password": "<%= password %>"
   ```

## Advanced Topics

### Dynamic Content Generation

```elixir
<%
  # You can write complex Elixir code
  servers = Enum.filter(all_servers, & &1.active)
  total_weight = Enum.sum(Enum.map(servers, & &1.weight))
%>

Total weight: <%= total_weight %>

<%= for server <- servers do %>
Server <%= server.name %> (<%= Float.round(server.weight / total_weight * 100, 2) %>%)
<% end %>
```

### Conditional Includes

```elixir
<%= if feature_flags.monitoring_enabled do %>
  [monitoring]
  endpoint = <%= monitoring.endpoint %>
  api_key = <%= monitoring.api_key %>
<% end %>

<%= if feature_flags.tracing_enabled do %>
  [tracing]
  collector = <%= tracing.collector %>
  sample_rate = <%= tracing.sample_rate || 0.1 %>
<% end %>
```

### Error Handling in Templates

```elixir
<%
  # Use try-rescue for complex operations
  try do
    parsed_config = Jason.decode!(json_config)
%>
Config loaded successfully
Servers: <%= length(parsed_config["servers"]) %>
<%
  rescue
    e -> Logger.error("Failed to parse config: #{inspect(e)}")
  end
%>
```

## Security Considerations

1. **File Permissions**: Always use restrictive permissions (0o600) for files containing secrets
2. **Backup Security**: Backup files (`.bak`) contain secrets - ensure they have same permissions
3. **Temporary Files**: Temporary files (`.tmp`) are cleaned up on error, but may briefly contain secrets
4. **Logs**: Template rendering errors may include partial content - review log security
5. **Reload Scripts**: Scripts have access to environment and may see secrets - secure scripts properly

## Getting Help

- **Documentation**: https://docs.secrethub.com
- **Issues**: https://github.com/secrethub/secrethub/issues
- **Community**: https://community.secrethub.com

## See Also

- [Agent Configuration Guide](agent-configuration.md)
- [Policy Management Guide](policies.md)
- [Secret Engines Guide](secret-engines.md)
