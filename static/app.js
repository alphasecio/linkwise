const MIN_PASSWORD_LENGTH = 8;

const $ = (id) => document.getElementById(id);
const authScreen = $('authScreen');
const appScreen = $('appScreen');
const emailInput = $('email');
const passwordInput = $('password');
const signInBtn = $('signInBtn');
const signUpBtn = $('signUpBtn');
const signOutBtn = $('signOutBtn');
const authError = $('authError');
const userEmail = $('userEmail');
const userMenuBtn = $('userMenuBtn');
const userMenu = $('userMenu');
const urlInput = $('urlInput');
const addLinkBtn = $('addLinkBtn');
const addBtnText = $('addBtnText');
const addBtnLoader = $('addBtnLoader');
const addLinkError = $('addLinkError');
const searchInput = $('searchInput');
const linksContainer = $('linksContainer');

let allLinks = [];

async function api(path, { method = 'GET', body } = {}) {
    const options = { method, credentials: 'same-origin', headers: {} };
    if (body !== undefined) {
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(body);
    }
    const res = await fetch(path, options);
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && path !== '/api/signin') showAuth();
    return { ok: res.ok, data };
}

function showAuth() {
    allLinks = [];
    linksContainer.replaceChildren();
    authScreen.classList.remove('hidden');
    appScreen.classList.add('hidden');
}

async function showApp(email) {
    emailInput.value = '';
    passwordInput.value = '';
    authError.textContent = '';
    userEmail.textContent = email;
    authScreen.classList.add('hidden');
    appScreen.classList.remove('hidden');
    await loadLinks();
}

async function checkAuth() {
    try {
        const { data } = await api('/api/me');
        if (data.authenticated) await showApp(data.email);
        else showAuth();
    } catch {
        showAuth();
    }
}

async function authenticate(path, fallbackError) {
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    if (!email || !password) { authError.textContent = 'Please enter email and password'; return; }
    if (path === '/api/signup' && password.length < MIN_PASSWORD_LENGTH) {
        authError.textContent = `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
        return;
    }
    authError.textContent = '';
    try {
        const { ok, data } = await api(path, { method: 'POST', body: { email, password } });
        if (ok) await showApp(data.email);
        else authError.textContent = data.error || fallbackError;
    } catch {
        authError.textContent = 'Network error. Please try again.';
    }
}

signInBtn.addEventListener('click', () => authenticate('/api/signin', 'Sign in failed'));
signUpBtn.addEventListener('click', () => authenticate('/api/signup', 'Sign up failed'));

signOutBtn.addEventListener('click', async () => {
    userMenu.classList.add('hidden');
    try {
        await api('/api/signout', { method: 'POST' });
        searchInput.value = '';
        showAuth();
    } catch (e) {
        console.error('Sign out failed', e);
    }
});

userMenuBtn.addEventListener('click', (e) => { e.stopPropagation(); userMenu.classList.toggle('hidden'); });
document.addEventListener('click', (e) => {
    if (!userMenu.classList.contains('hidden') && !userMenu.contains(e.target)) userMenu.classList.add('hidden');
});

addLinkBtn.addEventListener('click', async () => {
    const url = urlInput.value.trim();
    if (!url) { addLinkError.textContent = 'Please enter a URL'; return; }
    if (!isHttpUrl(url)) { addLinkError.textContent = 'Please enter a valid http(s) URL'; return; }

    addLinkError.textContent = '';
    addBtnText.textContent = 'Saving...';
    addBtnLoader.classList.remove('hidden');
    addLinkBtn.disabled = true;
    try {
        const { ok, data } = await api('/api/links', { method: 'POST', body: { url } });
        if (ok && data.success) {
            urlInput.value = '';
            allLinks.unshift(data.link);
            applyFilter();
        } else {
            addLinkError.textContent = data.error || 'Failed to add link';
        }
    } catch {
        addLinkError.textContent = 'Failed to add link. Please try again.';
    } finally {
        addBtnText.textContent = 'Save';
        addBtnLoader.classList.add('hidden');
        addLinkBtn.disabled = false;
    }
});

linksContainer.addEventListener('click', async (e) => {
    const button = e.target.closest('.delete-btn');
    if (!button || !confirm('Delete this link?')) return;
    const id = Number(button.dataset.id);
    try {
        const { ok } = await api(`/api/links/${id}`, { method: 'DELETE' });
        if (ok) {
            allLinks = allLinks.filter((l) => l.id !== id);
            applyFilter();
        }
    } catch (err) {
        console.error('Failed to delete link', err);
    }
});

async function loadLinks() {
    try {
        const { ok, data } = await api('/api/links');
        if (ok && data.success) {
            allLinks = data.links;
            applyFilter();
        }
    } catch (e) {
        console.error('Failed to load links:', e);
    }
}

function applyFilter() {
    const q = searchInput.value.toLowerCase().trim();
    const links = !q ? allLinks : allLinks.filter((l) =>
        [l.title, l.url, l.summary, ...l.tags].some((field) => field.toLowerCase().includes(q)));
    renderLinks(links, q ? 'No links match your search.' : 'No links saved yet. Add your first link above!');
}

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function renderLinks(links, emptyMessage) {
    if (!links.length) {
        const empty = el('div', 'empty-state');
        empty.append(el('p', null, emptyMessage));
        linksContainer.replaceChildren(empty);
        return;
    }
    linksContainer.replaceChildren(...links.map((link) => {
        const anchor = el('a', 'link-icon', '🔗');
        if (isHttpUrl(link.url)) anchor.href = link.url;
        anchor.target = '_blank';
        anchor.rel = 'noopener noreferrer';
        anchor.title = link.url;

        const title = el('div', 'link-title');
        title.append(anchor, el('span', null, link.title));

        const del = el('button', 'delete-btn', '×');
        del.type = 'button';
        del.title = 'Delete link';
        del.dataset.id = link.id;

        const header = el('div', 'link-header');
        header.append(title, del);

        const tags = el('div', 'link-tags');
        tags.append(...link.tags.slice(0, 6).map((t) => el('span', 'tag', `#${t}`)),
            el('span', 'link-date', formatDate(link.created_at)));

        const card = el('div', 'link-card');
        card.append(header, el('div', 'link-summary', link.summary), tags);
        return card;
    }));
}

searchInput.addEventListener('input', applyFilter);
emailInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') passwordInput.focus(); });
passwordInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') signInBtn.click(); });
urlInput.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !addLinkBtn.disabled) addLinkBtn.click(); });

function isHttpUrl(value) {
    try {
        const { protocol } = new URL(value);
        return protocol === 'http:' || protocol === 'https:';
    } catch {
        return false;
    }
}

function formatDate(dateString) {
    if (!dateString) return 'Just now';
    const d = new Date(dateString);
    const startOfDay = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate());
    const days = Math.round((startOfDay(new Date()) - startOfDay(d)) / 86400000);
    if (days <= 0) return 'Today';
    if (days === 1) return 'Yesterday';
    if (days < 7) return `${days} days ago`;
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

checkAuth();
