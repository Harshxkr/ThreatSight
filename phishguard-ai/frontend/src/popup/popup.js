fetch("http://localhost:8000/health")
  .then(response => response.json())
  .then(data => {
    document.getElementById("status").textContent =
      data.status === "ok" ? "Backend: connected ✓" : "Backend: unavailable";
  })
  .catch(() => {
    document.getElementById("status").textContent = "Backend: unavailable";
  });
