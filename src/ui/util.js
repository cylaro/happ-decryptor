export function t(en, ru) {
  return document.documentElement.lang === 'en' ? en : ru;
}

let noticeTimer;
export function showToast(message, kind = 'ok') {
  const node = document.getElementById('notice');
  node.textContent = message;
  node.dataset.kind = kind;
  node.classList.add('visible');
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => node.classList.remove('visible'), 3000);
}

export async function copyText(text) {
  if (!text) return false;
  try {
    await navigator.clipboard.writeText(text);
    showToast(t('Copied to clipboard', 'Скопировано в буфер'));
    return true;
  } catch {
    showToast(t('Clipboard access denied. Select and copy the result manually.', 'Доступ к буферу запрещён. Выделите и скопируйте результат вручную.'), 'error');
    return false;
  }
}
