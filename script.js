/* ── Mobile menu toggle ── */
const menu = document.querySelector('.menu');
const navBar = document.querySelector('.nav');
menu?.addEventListener('click', () => navBar.classList.toggle('open'));
document.querySelectorAll('nav a').forEach(a =>
  a.addEventListener('click', () => navBar.classList.remove('open'))
);

/* ── Scroll-reveal & stagger observer ── */
const revealObserver = new IntersectionObserver(
  entries => entries.forEach(e => {
    if (e.isIntersecting) e.target.classList.add('visible');
  }),
  { threshold: 0.08, rootMargin: '0px 0px -50px 0px' }
);
document.querySelectorAll('.reveal, .stagger').forEach(el => revealObserver.observe(el));

/* ── Active nav section highlight ── */
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('nav a[href^="#"]');
const sectionObserver = new IntersectionObserver(
  entries => entries.forEach(entry => {
    if (entry.isIntersecting) {
      const id = entry.target.id;
      navLinks.forEach(link =>
        link.classList.toggle('active', link.getAttribute('href') === '#' + id)
      );
    }
  }),
  { threshold: 0.2, rootMargin: '-76px 0px -50% 0px' }
);
sections.forEach(s => sectionObserver.observe(s));

/* ── Subtle header border glow on scroll ── */
let ticking = false;
window.addEventListener('scroll', () => {
  if (!ticking) {
    requestAnimationFrame(() => {
      navBar.style.borderBottomColor = window.scrollY > 60
        ? 'rgba(216,164,71,.15)'
        : '';
      ticking = false;
    });
    ticking = true;
  }
});
