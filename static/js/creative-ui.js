/**
 * creative-ui.js — DBERT Portal High-Performance Modern Experience Controller
 * Ultra-responsive, native 60/120fps scrolling with zero input lag.
 */

(function () {
  'use strict';

  // Check user motion preferences
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ---------------------------------------------------------------------------
  // 1. Native Smooth Scrolling & Zero-Lag Viewport Sync
  // ---------------------------------------------------------------------------
  function initScroll() {
    // Native browser scrolling ensures zero input latency on all devices
    document.documentElement.style.scrollBehavior = 'smooth';
    
    // Provide a safe fallback if any script references window.dbertLenis
    window.dbertLenis = {
      scrollTo: function (target, opts) {
        const el = typeof target === 'string' ? document.querySelector(target) : target;
        if (el) {
          el.scrollIntoView({ behavior: prefersReducedMotion ? 'auto' : 'smooth', block: 'start' });
        }
      },
      destroy: function () {}
    };
  }

  // ---------------------------------------------------------------------------
  // 2. Interactive Spotlight Glow (RAF-Throttled, Zero Reflow)
  // ---------------------------------------------------------------------------
  function initSpotlightCards() {
    const selector = '.spotlight-card, .jd-card, .hero-stat, .feature-card, .benefit-card, .dash-card';
    const cards = document.querySelectorAll(selector);

    cards.forEach((card) => {
      card.classList.add('spotlight-card');
      let rafId = null;

      card.addEventListener('mousemove', (e) => {
        if (rafId) return;
        rafId = requestAnimationFrame(() => {
          const rect = card.getBoundingClientRect();
          const x = e.clientX - rect.left;
          const y = e.clientY - rect.top;
          card.style.setProperty('--mouse-x', `${x}px`);
          card.style.setProperty('--mouse-y', `${y}px`);
          rafId = null;
        });
      }, { passive: true });

      card.addEventListener('mouseleave', () => {
        if (rafId) {
          cancelAnimationFrame(rafId);
          rafId = null;
        }
        card.style.removeProperty('--mouse-x');
        card.style.removeProperty('--mouse-y');
      }, { passive: true });
    });
  }

  // ---------------------------------------------------------------------------
  // 3. Lightweight Magnetic Actions (Subtle & Performant)
  // ---------------------------------------------------------------------------
  function initMagneticButtons() {
    if (prefersReducedMotion || typeof gsap === 'undefined') return;

    const magneticTargets = document.querySelectorAll('.btn-magnetic, .btn-hero-primary, .nav-cta');

    magneticTargets.forEach((btn) => {
      btn.classList.add('btn-magnetic');
      let rafId = null;

      btn.addEventListener('mousemove', (e) => {
        if (rafId) return;
        rafId = requestAnimationFrame(() => {
          const rect = btn.getBoundingClientRect();
          const centerX = rect.left + rect.width / 2;
          const centerY = rect.top + rect.height / 2;
          const deltaX = (e.clientX - centerX) * 0.18;
          const deltaY = (e.clientY - centerY) * 0.18;

          gsap.to(btn, {
            x: deltaX,
            y: deltaY,
            duration: 0.2,
            ease: 'power2.out',
            overwrite: 'auto'
          });
          rafId = null;
        });
      }, { passive: true });

      btn.addEventListener('mouseleave', () => {
        if (rafId) {
          cancelAnimationFrame(rafId);
          rafId = null;
        }
        gsap.to(btn, {
          x: 0,
          y: 0,
          duration: 0.35,
          ease: 'power3.out',
          overwrite: 'auto'
        });
      }, { passive: true });
    });
  }

  // ---------------------------------------------------------------------------
  // 4. GSAP Micro-Interactions (Staggered Hero Entrance)
  // ---------------------------------------------------------------------------
  function initGsapAnimations() {
    if (typeof gsap === 'undefined' || prefersReducedMotion) return;

    const hero = document.querySelector('.hero');
    if (hero) {
      const heroTl = gsap.timeline({ defaults: { ease: 'power2.out' } });

      const badge = hero.querySelector('.hero-badge');
      const heading = hero.querySelector('h1');
      const sub = hero.querySelector('.hero-sub');
      const ctas = hero.querySelector('.hero-cta-row');
      const stats = hero.querySelectorAll('.hero-stat, .hero-stat-badge');
      const heroVisual = hero.querySelector('.hero-visual-wrap');

      if (badge) heroTl.from(badge, { y: -12, opacity: 0, duration: 0.4 });
      if (heading) heroTl.from(heading, { y: 14, opacity: 0, duration: 0.45 }, '-=0.25');
      if (sub) heroTl.from(sub, { y: 10, opacity: 0, duration: 0.4 }, '-=0.3');
      if (ctas) heroTl.from(ctas, { y: 10, opacity: 0, duration: 0.4 }, '-=0.25');
      if (stats.length) {
        heroTl.from(stats, {
          y: 12,
          opacity: 0,
          stagger: 0.06,
          duration: 0.4,
          ease: 'power2.out'
        }, '-=0.2');
      }
      if (heroVisual) {
        heroTl.from(heroVisual, {
          scale: 0.96,
          opacity: 0,
          duration: 0.55,
          ease: 'power2.out'
        }, '-=0.4');
      }
    }
  }

  // ---------------------------------------------------------------------------
  // 5. Clean Topbar Scrolled Class
  // ---------------------------------------------------------------------------
  function initNavbarScroll() {
    const topbar = document.querySelector('.topbar');
    if (!topbar) return;

    let ticking = false;
    window.addEventListener('scroll', () => {
      if (!ticking) {
        requestAnimationFrame(() => {
          if (window.scrollY > 15) {
            topbar.classList.add('scrolled');
          } else {
            topbar.classList.remove('scrolled');
          }
          ticking = false;
        });
        ticking = true;
      }
    }, { passive: true });
  }

  // ---------------------------------------------------------------------------
  // Boot
  // ---------------------------------------------------------------------------
  function boot() {
    initScroll();
    initSpotlightCards();
    initMagneticButtons();
    initGsapAnimations();
    initNavbarScroll();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
