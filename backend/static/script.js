let state = {
  user_id: null,
  username: null,
  public_key: null,
  login_pin: null,
  search_pin: null,
  active_conversation: null,
  partner_label: null,
  conversations: [] // cache de la lista para lookup de labels
};

async function registerUser() {
  const username = document.getElementById('reg_username').value.trim();
  if (!username) { alert("Username required"); return; }
  const res = await fetch('/register', {
    method: 'POST',
    headers: {'Content-Type':'application/x-www-form-urlencoded'},
    body: `username=${encodeURIComponent(username)}`
  });
  const data = await res.json();
  if (data.error) { alert(data.error); return; }
  const box = document.getElementById('register_result');
  box.innerHTML = `
    <b>Account created</b><br/>
    Login PIN: <code>${data.login_pin}</code><br/>
    Search PIN: <code>${data.search_pin}</code><br/>
    <div class="hint">Tu private key quedó cifrada con tu Login PIN.</div>
  `;
}

async function login() {
  const pin = document.getElementById('login_pin').value.trim();
  if (!pin) { alert("Login PIN required"); return; }

  // Limpieza UI/estado antes de cargar nuevo usuario
  resetChatViews();
  clearConversations();
  state = { ...state, active_conversation: null, partner_label: null, conversations: [] };

  const res = await fetch('/login', {
    method: 'POST',
    headers: {'Content-Type':'application/x-www-form-urlencoded'},
    body: `login_pin=${encodeURIComponent(pin)}`
  });
  const data = await res.json();
  if (data.error) { alert(data.error); return; }

  state.user_id = data.user_id;
  state.username = data.username;
  state.public_key = data.public_key;
  state.login_pin = data.login_pin;
  state.search_pin = data.search_pin;

  document.getElementById('me_label').innerText = `${state.username} (you)`;
  document.getElementById('me_login_pin').innerText = state.login_pin;
  document.getElementById('me_search_pin').innerText = state.search_pin;

  document.getElementById('auth').style.display = 'none';
  document.getElementById('app').style.display = 'block';

  await loadConversations();
}

function logout() {
  state = {
    user_id: null, username: null, public_key: null,
    login_pin: null, search_pin: null,
    active_conversation: null, partner_label: null, conversations: []
  };
  clearConversations();
  resetChatViews();
  document.getElementById('auth').style.display = 'block';
  document.getElementById('app').style.display = 'none';
}

function clearConversations() {
  const el = document.getElementById('conv_list');
  if (el) el.innerHTML = '';
}

function resetChatViews() {
  const chatView = document.getElementById('chat_view');
  const chatBox = document.getElementById('chat_box');
  const chatHeader = document.getElementById('chat_header');
  if (chatView) chatView.innerHTML = '';
  if (chatHeader) chatHeader.innerText = '';
  if (chatBox) chatBox.style.display = 'none';
}

async function loadConversations() {
  if (!state.user_id) return;
  const res = await fetch(`/conversations/${state.user_id}`);
  const list = await res.json();
  state.conversations = Array.isArray(list) ? list : [];

  const el = document.getElementById('conv_list');
  el.innerHTML = '';
  state.conversations.forEach(item => {
    const a = document.createElement('button');
    a.className = 'conv';
    a.innerText = `${item.partner_username} (${item.partner_search_pin.slice(0,8)})`;
    a.onclick = () => openConversation(item.conversation_id, item.partner_username);
    el.appendChild(a);
  });
}

async function startConversation() {
  const pin = document.getElementById('partner_pin').value.trim();
  if (!pin) { alert("Partner search PIN required"); return; }
  const res = await fetch('/start_conversation', {
    method: 'POST',
    headers: {'Content-Type':'application/x-www-form-urlencoded'},
    body: `user_id=${encodeURIComponent(state.user_id)}&partner_search_pin=${encodeURIComponent(pin)}`
  });
  const data = await res.json();
  if (data.error) { alert(data.error); return; }

  // Recargar lista y abrir con label
  await loadConversations();
  const conv = state.conversations.find(c => c.conversation_id === data.conversation_id);
  const label = conv ? conv.partner_username : 'Chat';
  await openConversation(data.conversation_id, label);
}

async function openConversation(conversation_id, partnerLabel='Chat') {
  if (!conversation_id) return;
  state.active_conversation = conversation_id;
  state.partner_label = partnerLabel || 'Chat';

  // Preparar UI
  const header = document.getElementById('chat_header');
  const view = document.getElementById('chat_view');
  const box = document.getElementById('chat_box');
  if (header) header.innerText = `Conversation: ${state.partner_label}`;
  if (view) view.innerHTML = '';
  if (box) box.style.display = 'block';

  // Carga inicial: DESCIFRADO automático
  await loadMessages(true);
}

async function sendMessage() {
  const text = document.getElementById('msg_input').value;
  if (!text || !state.active_conversation) return;
  const res = await fetch('/send_message', {
    method: 'POST',
    headers: {'Content-Type':'application/x-www-form-urlencoded'},
    body: `conversation_id=${encodeURIComponent(state.active_conversation)}&sender_id=${encodeURIComponent(state.user_id)}&content=${encodeURIComponent(text)}`
  });
  const data = await res.json();
  if (data.error) { alert(data.error); return; }
  document.getElementById('msg_input').value = '';
  // Tras enviar, refrescamos DESCIFRADO automáticamente
  await loadMessages(true);
}

async function loadMessages(decryptNow) {
  const view = document.getElementById('chat_view');
  if (!state.active_conversation || !state.user_id) return;

  // 1) obtener mensajes encriptados
  const encRes = await fetch(`/messages/${state.active_conversation}?user_id=${encodeURIComponent(state.user_id)}`);
  const encList = await encRes.json();
  if (encList.error) { alert(encList.error); return; }

  // Si no era requerido descifrar (fallback)
  if (!decryptNow) {
    view.innerHTML = encList.map(m => renderBubble(`[encrypted] ${m.encrypted.slice(0,40)}…`, m.sender_id)).join('');
    return;
  }

  // 2) descifrado automático usando login_pin como key_password
  const decRes = await fetch('/messages_decrypted', {
    method: 'POST',
    headers: {'Content-Type':'application/x-www-form-urlencoded'},
    body: `conversation_id=${encodeURIComponent(state.active_conversation)}&user_id=${encodeURIComponent(state.user_id)}&key_password=${encodeURIComponent(state.login_pin)}`
  });
  const decList = await decRes.json();

  if (decList.error) {
    // Fallback silencioso a vista encriptada si algo falla
    view.innerHTML = encList.map(m => renderBubble(`[encrypted] ${m.encrypted.slice(0,40)}…`, m.sender_id)).join('');
    console.warn(decList.error);
    return;
  }

  view.innerHTML = decList.map(m => renderBubble(m.content, m.sender_id)).join('');
  view.scrollTop = view.scrollHeight;
}

function renderBubble(text, sender_id) {
  const mine = (sender_id === state.user_id);
  const cls = mine ? 'bubble mine' : 'bubble';
  return `<div class="${cls}">${escapeHTML(text)}</div>`;
}

function escapeHTML(s) {
  return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
