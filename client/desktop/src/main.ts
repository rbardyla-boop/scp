// SCP Desktop — Phase 3 reference client stub.
// Tauri 2.x frontend entry point.

document.addEventListener("DOMContentLoaded", () => {
  const status = document.getElementById("status");
  if (status) {
    // TODO Phase 3: invoke Rust core via Tauri commands
    status.textContent = "Identity layer ready (stub).";
  }
});
