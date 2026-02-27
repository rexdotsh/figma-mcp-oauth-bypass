# figma-mcp-oauth-bypass

Figma's MCP server only lets [recognized clients](https://www.figma.com/mcp-catalog/) (like Claude Code) through its OAuth registration. Everyone else gets a `403`.

This script pretends to be Claude Code, runs the OAuth flow in your browser, and saves the tokens so your actual client can use them.

## Why

Figma allowlists the `client_name` field during [dynamic client registration](https://datatracker.ietf.org/doc/html/rfc7591). If your MCP client sends anything other than a known name, the registration endpoint rejects it outright. There's no workaround on the client side; you need valid credentials first.

## How

```sh
bun run figma-oauth.ts
# or
npx tsx figma-oauth.ts
```

It registers as `"Claude Code"`, opens Figma's consent page in your browser, catches the redirect on `localhost:9876`, exchanges the code for tokens, and asks before writing anything to disk.

If it detects [OpenCode](https://github.com/anomalyco/opencode), it'll offer to write directly to its auth store. Either way, credentials are printed so you can configure any client manually.

No dependencies. Works with Bun or Node 18+.

## [OpenCode](https://github.com/anomalyco/opencode)

Add the Figma MCP server to your `opencode.json` config:

```json
{
  "mcp": {
    "figma": {
      "type": "remote",
      "url": "https://mcp.figma.com/mcp"
    }
  }
}
```

This goes in your [OpenCode config](https://opencode.ai/docs/config/) — run `opencode debug paths` to find it.

Then run the script. Tokens go into [`~/.local/share/opencode/mcp-auth.json`](https://github.com/anomalyco/opencode/blob/1d9f05e4f5cdda1d1aa9675444ee83c57ae9951e/packages/opencode/src/mcp/auth.ts#L32).

## Other clients

Tokens are printed after auth completes. Use them however your client expects. PRs to add auto-detection for more clients are welcome.
