import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "./",
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8036",
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    outDir: "../react-dist",
    emptyOutDir: true,
  },
});
