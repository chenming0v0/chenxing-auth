import path from "path";
import { fileURLToPath } from "url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const backendOrigin = "http://127.0.0.1:3000";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss(), viteSingleFile()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  server: {
    port: 5175,
    strictPort: true,
    proxy: {
      "/api": backendOrigin,
      "/health": backendOrigin,
      "/.well-known": backendOrigin,
      // Exact OAuth protocol paths only; /oauth/consent stays on Vite's SPA fallback.
      "/oauth/authorize": backendOrigin,
      "/oauth/token": backendOrigin,
      "/oauth/revoke": backendOrigin,
      "/oauth/userinfo": backendOrigin,
      "/auth/external": backendOrigin,
    },
  },
});
