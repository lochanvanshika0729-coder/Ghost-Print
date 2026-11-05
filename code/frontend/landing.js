(() => {
  const root = document.documentElement;
  const menuButton = document.querySelector('.gg-menu-toggle');
  const navigation = document.querySelector('#gg-navigation');
  const frame = document.querySelector('.gg-product-frame');
  const previewButtons = [...document.querySelectorAll('[data-preview]')];

  root.classList.add('gg-js');

  function closeMenu() {
    if (!menuButton || !navigation) return;
    navigation.classList.remove('is-open');
    menuButton.setAttribute('aria-expanded', 'false');
    menuButton.setAttribute('aria-label', 'Open navigation');
  }

  menuButton?.addEventListener('click', () => {
    const open = menuButton.getAttribute('aria-expanded') !== 'true';
    menuButton.setAttribute('aria-expanded', String(open));
    menuButton.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    navigation?.classList.toggle('is-open', open);
  });

  navigation?.querySelectorAll('a').forEach(link => link.addEventListener('click', closeMenu));
  window.addEventListener('keydown', event => {
    if (event.key === 'Escape') closeMenu();
  });
  window.addEventListener('resize', () => {
    if (window.innerWidth > 760) closeMenu();
  }, { passive: true });

  previewButtons.forEach(button => button.addEventListener('click', () => {
    if (!frame) return;
    const view = button.dataset.preview;
    if (!/^(overview|audits|lineage|risk|forensics|certificates|reports)$/.test(view || '')) return;
    previewButtons.forEach(item => item.setAttribute('aria-pressed', String(item === button)));
    frame.title = `Live preview of the Ghost Print ${button.textContent.trim()} dashboard`;
    frame.src = `/dashboard#${view}`;
  }));

  const revealItems = document.querySelectorAll('[data-reveal]');
  if (!('IntersectionObserver' in window) || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    revealItems.forEach(item => item.classList.add('is-visible'));
  } else {
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -28px 0px' });
    revealItems.forEach(item => observer.observe(item));
  }

  document.querySelectorAll('a[href^="#"]').forEach(link => link.addEventListener('click', event => {
    const selector = link.getAttribute('href');
    if (!selector || selector === '#') return;
    let target;
    try { target = document.querySelector(selector); } catch { return; }
    if (!target) return;
    event.preventDefault();
    target.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
    if (history.replaceState) history.replaceState(null, '', selector);
  }));
})();
