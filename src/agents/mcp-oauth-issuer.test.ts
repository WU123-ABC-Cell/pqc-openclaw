import path from "node:path";
import { withTempHome as withBaseTempHome } from "openclaw/plugin-sdk/test-env";
import { afterEach, describe, expect, it, vi } from "vitest";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";
import { createMcpOAuthClientProvider } from "./mcp-oauth-provider.js";
import {
  readMcpOAuthStore,
  resolveMcpOAuthStoreKey,
  updateMcpOAuthStore,
  type McpOAuthStore,
} from "./mcp-oauth-store.js";
import {
  clearMcpOAuthCredentials,
  readMcpOAuthCredentialsStatus,
  resolveMcpOAuthAccessToken,
  runMcpOAuthLogin,
} from "./mcp-oauth.js";

const serverName = "Remote Docs";
const serverUrl = "https://mcp.example.com/mcp";
const issuer = "https://auth.example.com";

async function withIsolatedState(run: () => Promise<void>): Promise<void> {
  await withBaseTempHome(
    async (home) => {
      const previousStateDir = process.env.OPENCLAW_STATE_DIR;
      process.env.OPENCLAW_STATE_DIR = path.join(home, ".openclaw");
      closeOpenClawStateDatabaseForTest();
      try {
        await run();
      } finally {
        closeOpenClawStateDatabaseForTest();
        if (previousStateDir === undefined) {
          delete process.env.OPENCLAW_STATE_DIR;
        } else {
          process.env.OPENCLAW_STATE_DIR = previousStateDir;
        }
      }
    },
    {
      prefix: "openclaw-mcp-oauth-issuer-",
      skipSessionCleanup: true,
      env: { OPENCLAW_CONFIG_PATH: undefined, OPENCLAW_STATE_DIR: undefined },
    },
  );
}

afterEach(() => closeOpenClawStateDatabaseForTest());

describe("MCP OAuth authorization-server binding", () => {
  it.each([undefined, null, 123, { url: issuer }, "", "not-a-url"])(
    "blocks old or malformed issuer %s before using tokens or client secrets",
    async (untrustedIssuer) => {
      await withIsolatedState(async () => {
        const storeKey = resolveMcpOAuthStoreKey(serverName, serverUrl);
        updateMcpOAuthStore(
          storeKey,
          () =>
            ({
              clientInformation: {
                client_id: "old-client",
                client_secret: "fake-old-secret",
                ...(untrustedIssuer !== undefined ? { issuer: untrustedIssuer } : {}),
              },
              tokens: {
                access_token: "fake-old-access",
                refresh_token: "fake-old-refresh",
                token_type: "Bearer",
                ...(untrustedIssuer !== undefined ? { issuer: untrustedIssuer } : {}),
              },
              tokenExpiresAt: Date.now() + 60_000,
            }) as McpOAuthStore,
        );
        const fetchFn = vi.fn();
        const provider = createMcpOAuthClientProvider({ serverName, serverUrl });
        const recovery =
          "Run openclaw mcp logout Remote Docs, then openclaw mcp login Remote Docs.";

        expect(() => provider.clientInformation()).toThrow(recovery);
        expect(() => provider.tokens()).toThrow(recovery);
        await expect(
          resolveMcpOAuthAccessToken({ serverName, serverUrl, fetchFn }),
        ).rejects.toThrow(recovery);
        await expect(runMcpOAuthLogin({ serverName, serverUrl, fetchFn })).rejects.toThrow(
          recovery,
        );
        expect(fetchFn).not.toHaveBeenCalled();
        expect(readMcpOAuthStore(storeKey).tokens?.refresh_token).toBe("fake-old-refresh");
        await expect(
          readMcpOAuthCredentialsStatus({ serverName, serverUrl }),
        ).resolves.toMatchObject({
          hasTokens: true,
          hasUnboundCredentials: true,
        });

        await clearMcpOAuthCredentials({ serverName, serverUrl });
        expect(readMcpOAuthStore(storeKey)).toEqual({ credentialState: "cleared" });
        await expect(
          readMcpOAuthCredentialsStatus({ serverName, serverUrl }),
        ).resolves.toMatchObject({
          hasTokens: false,
          hasUnboundCredentials: false,
        });
      });
    },
  );

  it("allows a newly bound fresh token and retains the client secret for its issuer", async () => {
    await withIsolatedState(async () => {
      const provider = createMcpOAuthClientProvider({ serverName, serverUrl });
      await provider.saveClientInformation?.({
        client_id: "bound-client",
        client_secret: "fake-bound-secret",
        issuer,
      });
      await provider.saveTokens({
        access_token: "fake-bound-access",
        refresh_token: "fake-bound-refresh",
        token_type: "Bearer",
        expires_in: 3600,
        issuer,
      });
      expect(provider.clientInformation()).toMatchObject({ issuer });
      expect(provider.tokens()).toMatchObject({ issuer, access_token: "fake-bound-access" });
      await expect(resolveMcpOAuthAccessToken({ serverName, serverUrl })).resolves.toBe(
        "fake-bound-access",
      );
      await expect(readMcpOAuthCredentialsStatus({ serverName, serverUrl })).resolves.toMatchObject(
        {
          hasTokens: true,
          hasUnboundCredentials: false,
        },
      );
    });
  });

  it("requires both the token and client secret to have their own binding", async () => {
    await withIsolatedState(async () => {
      const storeKey = resolveMcpOAuthStoreKey(serverName, serverUrl);
      const boundClient = { client_id: "client", client_secret: "fake-secret", issuer };
      const boundTokens = {
        access_token: "fake-access",
        refresh_token: "fake-refresh",
        token_type: "Bearer" as const,
        issuer,
      };
      const provider = createMcpOAuthClientProvider({ serverName, serverUrl });
      updateMcpOAuthStore(storeKey, () => ({
        clientInformation: boundClient,
        tokens: { ...boundTokens, issuer: undefined },
      }));
      expect(() => provider.clientInformation()).toThrow("mcp logout Remote Docs");
      expect(() => provider.tokens()).toThrow("mcp logout Remote Docs");

      updateMcpOAuthStore(storeKey, () => ({
        clientInformation: { ...boundClient, issuer: undefined },
        tokens: boundTokens,
      }));
      expect(() => provider.clientInformation()).toThrow("mcp logout Remote Docs");
      expect(() => provider.tokens()).toThrow("mcp logout Remote Docs");
    });
  });

  it("records the discovered authorization server on a new real-SDK login", async () => {
    await withIsolatedState(async () => {
      const fetchFn = vi.fn(async (input: string | URL): Promise<Response> => {
        const url = new URL(input);
        const json = (value: unknown) =>
          new Response(JSON.stringify(value), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        if (url.hostname === "mcp.example.com") {
          return json({ resource: serverUrl, authorization_servers: [issuer] });
        }
        if (url.pathname.includes(".well-known")) {
          return json({
            issuer,
            authorization_endpoint: `${issuer}/authorize`,
            token_endpoint: `${issuer}/token`,
            registration_endpoint: `${issuer}/register`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code", "refresh_token"],
            code_challenge_methods_supported: ["S256"],
            token_endpoint_auth_methods_supported: ["none"],
          });
        }
        if (url.pathname === "/register") {
          return json({
            client_id: "new-client",
            redirect_uris: ["http://127.0.0.1:8989/oauth/callback"],
          });
        }
        if (url.pathname === "/token") {
          return json({
            access_token: "new-access",
            refresh_token: "new-refresh",
            token_type: "Bearer",
          });
        }
        throw new Error(`Unexpected OAuth request: ${url.origin}${url.pathname}`);
      });
      const authorizationUrls: URL[] = [];
      await expect(
        runMcpOAuthLogin({
          serverName,
          serverUrl,
          fetchFn,
          onAuthorizationUrl: (url) => {
            authorizationUrls.push(url);
          },
        }),
      ).resolves.toBe("redirect");
      expect(authorizationUrls).toHaveLength(1);
      expect(authorizationUrls[0]?.origin).toBe(issuer);
      const storeKey = resolveMcpOAuthStoreKey(serverName, serverUrl);
      expect(readMcpOAuthStore(storeKey).clientInformation?.issuer).toBe(issuer);

      await expect(
        runMcpOAuthLogin({ serverName, serverUrl, authorizationCode: "fake-code", fetchFn }),
      ).resolves.toBe("authorized");
      expect(readMcpOAuthStore(storeKey).tokens).toMatchObject({
        access_token: "new-access",
        refresh_token: "new-refresh",
        issuer,
      });
      expect(fetchFn.mock.calls.some(([input]) => new URL(input).pathname === "/token")).toBe(true);
    });
  });

  it("does not send bound refresh credentials to a different discovered server", async () => {
    await withIsolatedState(async () => {
      const otherIssuer = "https://other-auth.example.com";
      const refreshToken = "fake-bound-refresh-sensitive";
      const clientSecret = "fake-bound-client-sensitive";
      const provider = createMcpOAuthClientProvider({ serverName, serverUrl });
      await provider.saveClientInformation?.({
        client_id: "bound-client",
        client_secret: clientSecret,
        issuer,
      });
      await provider.saveTokens({
        access_token: "fake-expired-access",
        refresh_token: refreshToken,
        token_type: "Bearer",
        expires_in: -1,
        issuer,
      });
      const requests: Array<{ origin: string; body: string; authorization: string | null }> = [];
      const fetchFn = vi.fn(async (input: string | URL, init?: RequestInit): Promise<Response> => {
        const url = new URL(input);
        requests.push({
          origin: url.origin,
          body: String(init?.body ?? ""),
          authorization: new Headers(init?.headers).get("authorization"),
        });
        const json = (value: unknown) =>
          new Response(JSON.stringify(value), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        if (url.hostname === "mcp.example.com") {
          return json({ resource: serverUrl, authorization_servers: [otherIssuer] });
        }
        if (url.pathname.includes(".well-known")) {
          return json({
            issuer: otherIssuer,
            authorization_endpoint: `${otherIssuer}/authorize`,
            token_endpoint: `${otherIssuer}/token`,
            registration_endpoint: `${otherIssuer}/register`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code", "refresh_token"],
            code_challenge_methods_supported: ["S256"],
            token_endpoint_auth_methods_supported: ["none"],
          });
        }
        if (url.pathname === "/register") {
          return json({
            client_id: "other-client",
            redirect_uris: ["http://127.0.0.1:8989/oauth/callback"],
          });
        }
        throw new Error("Unexpected token request in mismatch proof");
      });

      await expect(
        resolveMcpOAuthAccessToken({
          serverName,
          serverUrl,
          resourceMetadataUrl: new URL(`${serverUrl}/metadata`),
          fetchFn,
        }),
      ).rejects.toThrow();
      expect(requests.some((request) => request.origin === otherIssuer)).toBe(true);
      expect(requests.every((request) => !request.body.includes(refreshToken))).toBe(true);
      expect(requests.every((request) => !request.body.includes(clientSecret))).toBe(true);
      expect(requests.every((request) => !request.authorization?.includes(clientSecret))).toBe(
        true,
      );
    });
  });
});
