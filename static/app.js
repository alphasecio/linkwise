let currentUser = null;
let allLinks = [];

const authScreen = document.getElementById('authScreen');
const appScreen = document.getElementById('appScreen');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const signInBtn = document.getElementById('signInBtn');
const signUpBtn = document.getElementById('signUpBtn');
const signOutBtn = document.getElementById('signOutBtn');
const authError = document.getElementById('authError');
const userEmail = document.getElementById('userEmail');
const userMenuBtn = document.getElementById('userMenuBtn');
const userMenu = document.getElementById('userMenu');
const urlInput = document.getElementById('urlInput');
const addLinkBtn = document.getElementById('addLinkBtn');
const addBtnText = document.getElementById('addBtnText');
const addBtnLoader = document.getElementById('addBtnLoader');
const addLinkError = document.getElementById('addLinkError');
const searchInput = document.getElementById('searchInput');
const linksContainer = document.getElementById('linksContainer');

userMenuBtn.addEventListener('click', e => { e.stopPropagation(); userMenu.classList.toggle('hidden'); });
document.addEventListener('click', e => { if (!userMenu.classList.contains('hidden') && !userMenu.contains(e.target)) userMenu.classList.add('hidden'); });

async function checkAuth() {
    try {
        const res = await fetch('/api/me', { credentials: 'include' });
        const data = await res.json();
        if (data.authenticated) { currentUser = { email: data.email }; showApp(); await loadLinks(); } 
        else showAuth();
    } catch { showAuth(); }
}

function showAuth() { authScreen.classList.remove('hidden'); appScreen.classList.add('hidden'); }
function showApp() { authScreen.classList.add('hidden'); appScreen.classList.remove('hidden'); userEmail.textContent = currentUser.email; }

signUpBtn.addEventListener('click', async () => {
    const email = emailInput.value.trim(), password = passwordInput.value;
    if (!email || !password) { authError.textContent='Please enter email and password'; return; }
    if (password.length<6) { authError.textContent='Password must be at least 6 characters'; return; }
    try {
        authError.textContent='';
        const res = await fetch('/api/signup', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'include', body:JSON.stringify({email,password}) });
        const data = await res.json();
        if (res.ok) { currentUser={email:data.email}; emailInput.value=''; passwordInput.value=''; showApp(); await loadLinks(); } 
        else authError.textContent=data.error||'Sign up failed';
    } catch { authError.textContent='Network error. Please try again.'; }
});

signInBtn.addEventListener('click', async () => {
    const email=emailInput.value.trim(), password=passwordInput.value;
    if(!email||!password){ authError.textContent='Please enter email and password'; return; }
    try {
        authError.textContent='';
        const res=await fetch('/api/signin',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({email,password})});
        const data=await res.json();
        if(res.ok){ currentUser={email:data.email}; emailInput.value=''; passwordInput.value=''; showApp(); await loadLinks(); } 
        else authError.textContent=data.error||'Sign in failed';
    } catch { authError.textContent='Network error. Please try again.'; }
});

signOutBtn.addEventListener('click', async ()=>{
    userMenu.classList.add('hidden'); 
    try { await fetch('/api/signout',{method:'POST',credentials:'include'}); currentUser=null; allLinks=[]; showAuth(); } 
    catch(e){ console.error('Sign out failed',e); }
});

addLinkBtn.addEventListener('click', async ()=>{
    const url=urlInput.value.trim();
    if(!url){ addLinkError.textContent='Please enter a URL'; return; }
    if(!isValidUrl(url)){ addLinkError.textContent='Please enter a valid URL'; return; }
    try{
        addLinkError.textContent=''; addBtnText.textContent='Saving...'; addBtnLoader.classList.remove('hidden'); addLinkBtn.disabled=true;
        const res=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({url})});
        const data=await res.json();
        if(res.ok&&data.success){ urlInput.value=''; await loadLinks(); } 
        else addLinkError.textContent=data.error||'Failed to add link';
    } catch { addLinkError.textContent='Failed to add link. Please try again.'; }
    finally { addBtnText.textContent='Save'; addBtnLoader.classList.add('hidden'); addLinkBtn.disabled=false; }
});

async function loadLinks(){
    try{
        const res=await fetch('/api/links',{credentials:'include'});
        const data=await res.json();
        if(data.success){ allLinks=data.links; renderLinks(allLinks); }
    } catch(e){ console.error('Failed to load links:', e); }
}

function renderLinks(links){
    if(!links.length){
        linksContainer.innerHTML='<div class="empty-state"><p>No links found.</p></div>';
        return;
    }
    linksContainer.innerHTML = links.map(link => `
        <div class="link-card" data-link-id="${link.id}">
            <div class="link-header">
                <div style="flex: 1;">
                    <div class="link-title">
                        <a href="${escapeHtml(link.url)}" target="_blank" rel="noopener noreferrer" class="link-icon" title="${escapeHtml(link.url)}">🔗</a>
                        <span>${escapeHtml(link.title)}</span>
                    </div>
                </div>
                <div style="display: flex; flex-direction: column; align-items: flex-end;">
                    <button class="delete-btn" onclick="deleteLink(${link.id})" title="Delete link">×</button>
                </div>
            </div>
            <div class="link-summary">${escapeHtml(link.summary)}</div>
            <div class="link-tags">
                ${link.tags.slice(0,6).map(tag => `<span class="tag">#${escapeHtml(tag)}</span>`).join('')}
                <span class="link-date">${formatDate(link.created_at)}</span>
            </div>
        </div>
    `).join('');
}

window.deleteLink=async (id)=>{ if(!confirm('Delete this link?')) return; try{ const res=await fetch(`/api/links/${id}`,{method:'DELETE',credentials:'include'}); const data=await res.json(); if(data.success) await loadLinks(); } catch(e){ console.error('Failed to delete link',e); } };

searchInput.addEventListener('input', e=>{
    const q=e.target.value.toLowerCase().trim();
    if(!q){ renderLinks(allLinks); return; }
    renderLinks(allLinks.filter(l=>l.title.toLowerCase().includes(q)||l.url.toLowerCase().includes(q)||l.summary.toLowerCase().includes(q)||l.tags.some(t=>t.toLowerCase().includes(q))));
});

emailInput.addEventListener('keypress',e=>{ if(e.key==='Enter') passwordInput.focus(); });
passwordInput.addEventListener('keypress',e=>{ if(e.key==='Enter') signInBtn.click(); });
urlInput.addEventListener('keypress',e=>{ if(e.key==='Enter') addLinkBtn.click(); });

function isValidUrl(string){ try{ new URL(string); return true; } catch{return false; } }
function escapeHtml(text){ if(text==null) return''; const div=document.createElement('div'); div.textContent=text; return div.innerHTML; }
function formatDate(dateString){ if(!dateString) return 'Just now'; const d=new Date(dateString), now=new Date(), diff=now-d, days=Math.floor(diff/(1000*60*60*24)); return days===0?'Today':days===1?'Yesterday':days<7?`${days} days ago`:d.toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'}); }

checkAuth();
