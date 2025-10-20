# Bun Quick Reference for SecretHub

**Why Bun?**
- ⚡ **Much faster** than npm/yarn (10-100x faster installs)
- 🔋 **Batteries included** - bundler, transpiler, test runner built-in
- 🎯 **Drop-in replacement** - compatible with npm packages
- 🦾 **Better DX** - faster feedback loops

---

## 📦 Installation Commands

### Common npm → Bun equivalents:

| npm | Bun | What it does |
|-----|-----|--------------|
| `npm install` | `bun install` | Install all dependencies |
| `npm install <pkg>` | `bun add <pkg>` | Add a package |
| `npm install -D <pkg>` | `bun add -d <pkg>` | Add dev dependency |
| `npm uninstall <pkg>` | `bun remove <pkg>` | Remove a package |
| `npm run <script>` | `bun run <script>` | Run a script |
| `npm run build` | `bun run build` | Build the project |
| `npm run dev` | `bun run dev` | Start dev server |
| `npm test` | `bun test` | Run tests |

---

## 🚀 SecretHub-Specific Commands

### For Phoenix Assets (in `apps/secrethub_web/assets/`)

```bash
# Install all dependencies
cd apps/secrethub_web/assets
bun install

# Or use the helper script from anywhere:
assets-install

# Add a new package
cd apps/secrethub_web/assets
bun add alpinejs

# Add a dev dependency
bun add -d tailwindcss

# Run build script (defined in package.json)
bun run build

# Or use the helper:
assets-build

# Watch mode for development
bun run watch
```

---

## 📝 package.json Scripts

When you create `apps/secrethub_web/assets/package.json`, it might look like:

```json
{
  "name": "secrethub-web-assets",
  "version": "0.1.0",
  "scripts": {
    "build": "bun build app.js --outdir=../priv/static/assets --minify",
    "watch": "bun build app.js --outdir=../priv/static/assets --watch",
    "deploy": "bun run build"
  },
  "dependencies": {
    "phoenix": "file:../../../deps/phoenix",
    "phoenix_html": "file:../../../deps/phoenix_html",
    "phoenix_live_view": "file:../../../deps/phoenix_live_view"
  },
  "devDependencies": {
    "tailwindcss": "^3.4.0"
  }
}
```

Then run scripts with:
```bash
bun run build
bun run watch
```

---

## 🎯 Bun Features You'll Love

### 1. Built-in TypeScript Support
No need for ts-node or compilation step:
```bash
bun run script.ts  # Just works!
```

### 2. Built-in Test Runner
```javascript
// test/example.test.js
import { test, expect } from "bun:test";

test("2 + 2", () => {
  expect(2 + 2).toBe(4);
});
```

Run with:
```bash
bun test
```

### 3. Fast File I/O
```javascript
// Read file (much faster than Node.js)
const file = Bun.file("data.json");
const data = await file.json();

// Write file
await Bun.write("output.json", JSON.stringify(data));
```

### 4. Environment Variables
```javascript
// Access env vars
const apiKey = Bun.env.API_KEY;

// Or use process.env (Node.js compatible)
const dbUrl = process.env.DATABASE_URL;
```

---

## 🔧 Common Tasks

### Update all dependencies
```bash
bun update
```

### Check for outdated packages
```bash
bun outdated
```

### Run with specific Bun version
```bash
bun --version  # Check version
bunx create-remix  # Run packages without installing
```

### Clean install (remove node_modules and reinstall)
```bash
rm -rf node_modules bun.lockb
bun install
```

---

## 🐛 Troubleshooting

### Issue: Package not found
```bash
# Make sure you're in the assets directory
cd apps/secrethub_web/assets

# Clear cache and reinstall
rm -rf node_modules bun.lockb
bun install
```

### Issue: Script not found
```bash
# Check package.json has the script defined
cat package.json | grep scripts -A 10

# Run directly
bun run <script-name>
```

### Issue: Phoenix can't find compiled assets
```bash
# Make sure assets are built
cd apps/secrethub_web/assets
bun run build

# Check output directory
ls -la ../priv/static/assets/
```

---

## 📚 Useful Links

- **Bun Docs:** https://bun.sh/docs
- **Package Manager:** https://bun.sh/docs/cli/install
- **Runtime:** https://bun.sh/docs/runtime
- **Bundler:** https://bun.sh/docs/bundler

---

## 💡 Pro Tips

1. **Bun is a drop-in replacement** - Your existing npm packages work fine
2. **Lock file** - Bun uses `bun.lockb` (commit this to git)
3. **Speed** - First install might download packages, subsequent ones are cached
4. **Workspaces** - Bun supports monorepos/workspaces like npm
5. **Scripts** - You can use Bun to run any JavaScript/TypeScript file directly

---

## 🎓 Example: Setting Up Phoenix Assets with Bun

```bash
# 1. Navigate to assets directory
cd apps/secrethub_web/assets

# 2. Initialize if needed (or use existing package.json)
# bun init

# 3. Install Phoenix dependencies
bun add phoenix phoenix_html phoenix_live_view

# 4. Install Tailwind CSS
bun add -d tailwindcss

# 5. Create build script in package.json
# (See example above)

# 6. Build assets
bun run build

# 7. Start Phoenix server (from root)
cd ../../..
mix phx.server
```

---

**Remember:** In SecretHub, always use the helper commands:
- `assets-install` (from anywhere)
- `assets-build` (from anywhere)

This ensures consistency across the team! 🚀

