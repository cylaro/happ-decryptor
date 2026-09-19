import { initEditor } from './ui/editor.js';
import './style.css';

const root = document.documentElement;
root.dataset.lang = ['ru', 'en'].includes(root.dataset.lang) ? root.dataset.lang : 'ru';
const language = document.getElementById('language');
function syncLanguage() {
  root.lang = root.dataset.lang;
  language.textContent = root.lang === 'ru' ? 'ENG' : 'RU';
  document.dispatchEvent(new Event('langchange'));
}
language.addEventListener('click', () => {
  root.dataset.lang = root.lang === 'ru' ? 'en' : 'ru';
  try { localStorage.setItem('happ-lang', root.dataset.lang); } catch { /* storage is optional */ }
  syncLanguage();
});
function route() {
  const requested = location.hash.replace(/^#\/?/, '');
  const view = ['workspace', 'request', 'guide'].includes(requested) ? requested : 'workspace';
  document.querySelectorAll('.view').forEach((node) => node.classList.toggle('active', node.id === `view-${view}`));
  document.querySelectorAll('.nav-link').forEach((link) => {
    const active = link.hash === `#/${view}`;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
  });
}
window.addEventListener('hashchange', route);
syncLanguage();
initEditor();
route();
