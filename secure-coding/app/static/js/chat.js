(function () {
  const box = document.getElementById("chat");
  if (!box) return;
  const mode = box.dataset.mode;              // "global" | "private"
  const target = box.dataset.target || null;  // 1:1 상대 user_id
  const list = document.getElementById("messages");
  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");
  const socket = io();

  function add(sender, content) {
    const li = document.createElement("li");
    const s = document.createElement("strong");
    s.textContent = sender + ": ";
    li.appendChild(s);
    // textContent 로 삽입 → 서버가 준 값이 HTML로 해석되지 않음 (XSS 방지)
    li.appendChild(document.createTextNode(content));
    list.appendChild(li);
    list.scrollTop = list.scrollHeight;
  }

  const eventName = mode === "global" ? "global_message" : "private_message";
  socket.on(eventName, (d) => add(d.sender, d.content));
  socket.on("error_message", (d) => window.alert(d.error));

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const content = input.value.trim();
    if (!content) return;
    if (mode === "global") {
      socket.emit("global_message", { content: content });
    } else {
      socket.emit("private_message", { to: target, content: content });
    }
    input.value = "";
  });
})();
