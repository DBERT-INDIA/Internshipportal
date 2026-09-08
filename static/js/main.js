const BASE_URL = window.location.pathname.includes('/results') ? '/results' : '';
let currentIntern   = null;
let currentBatchInfo = null;

// ===== PARTICLES =====
(function createParticles() {
  const hero = document.querySelector('.hero');
  if (!hero) return;
  const grid = document.createElement('div');
  grid.className = 'grid-overlay';
  hero.appendChild(grid);
  for (let i = 0; i < 18; i++) {
    const p    = document.createElement('div');
    p.className = 'particle';
    const size  = Math.random() * 4 + 1;
    p.style.cssText = `
      width:${size}px;height:${size}px;
      left:${Math.random()*100}%;
      animation-duration:${Math.random()*20+10}s;
      animation-delay:${Math.random()*10}s;
    `;
    hero.appendChild(p);
  }
})();

// ===== CONFETTI STYLE =====
const confettiStyle = document.createElement('style');
confettiStyle.textContent = `
  @keyframes confetti-fall {
    0%   { transform: translateY(0)     rotate(0deg);   opacity:1; }
    100% { transform: translateY(300px) rotate(720deg); opacity:0; }
  }
`;
document.head.appendChild(confettiStyle);

// ===== DOM READY =====
document.addEventListener('DOMContentLoaded', function () {

  // ── Hamburger ────────────────────────────────────────────────────────────
  const ham      = document.getElementById('hamburger');
  const navLinks = document.getElementById('navLinks');
  if (ham && navLinks) {
    ham.addEventListener('click', () => navLinks.classList.toggle('active'));
  }

  // ── Initial counter fetch ─────────────────────────────────────────────────
  fetchCounter();

  // ── Drag & drop on upload zone ────────────────────────────────────────────
  const dropArea = document.getElementById('dropArea');
  if (dropArea) {
    dropArea.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropArea.style.borderColor = 'rgba(226,185,111,0.8)';
    });
    dropArea.addEventListener('dragleave', () => {
      dropArea.style.borderColor = '';
    });
    dropArea.addEventListener('drop', (e) => {
      e.preventDefault();
      dropArea.style.borderColor = '';
      const files = e.dataTransfer.files;
      if (files && files[0]) {
        try {
          document.getElementById('payment_screenshot').files = files;
        } catch (_) {}
        handleFileSelect({ files });
      }
    });
  }

  // ── Enrollment form submit ────────────────────────────────────────────────
  const form = document.getElementById('enrollmentForm');
  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      const errDiv        = document.getElementById('form-error');
      const submitBtn     = document.getElementById('submitBtn');
      const submitText    = document.getElementById('submitText');
      const submitSpinner = document.getElementById('submitSpinner');

      errDiv.style.display = 'none';

      const fileInput = document.getElementById('payment_screenshot');
      if (!fileInput || !fileInput.files || !fileInput.files[0]) {
        errDiv.textContent   = '⚠ Please upload your payment screenshot.';
        errDiv.style.display = 'block';
        return;
      }

      submitText.style.display    = 'none';
      submitSpinner.style.display = 'flex';
      submitBtn.disabled          = true;

      const formData = new FormData(form);
      fetch(BASE_URL + '/enroll', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
          submitText.style.display    = 'inline';
          submitSpinner.style.display = 'none';
          submitBtn.disabled          = false;

          if (data.status === 'success') {
            closeModal();

            if (data.joining_date) {
              const sdEl = document.getElementById('success-batch-date');
              if (sdEl) sdEl.textContent = data.joining_date;
            }

            const msgEl = document.getElementById('success-msg');
            if (msgEl) {
              msgEl.innerHTML =
                'Hi <strong>' + (data.name || '') + '</strong>, your enrollment has been received! ' +
                'We have sent a confirmation to your email. Our team will verify your payment ' +
                'within 24 hours and dispatch your offer letter.';
            }

            document.getElementById('successModal').style.display = 'flex';
            document.body.style.overflow = 'hidden';

            // Refresh counter after new enrollment
            fetch(BASE_URL + '/enrollment-count?_=' + Date.now())
              .then(r => r.json())
              .then(d => animateCounter(parseInt(d.total_enrolled) || 0))
              .catch(() => {});

          } else {
            errDiv.textContent   = '⚠ ' + (data.message || 'Something went wrong. Please try again.');
            errDiv.style.display = 'block';
          }
        })
        .catch(() => {
          submitText.style.display    = 'inline';
          submitSpinner.style.display = 'none';
          submitBtn.disabled          = false;
          errDiv.textContent          = 'Network error. Please try again.';
          errDiv.style.display        = 'block';
        });
    });
  }

  // ── Close modal on overlay click ──────────────────────────────────────────
  document.addEventListener('click', function (e) {
    if (e.target.classList.contains('modal-overlay')) {
      e.target.style.display       = 'none';
      document.body.style.overflow = '';
    }
  });
});

// ===== COUNTER =====
function fetchCounter() {
  fetch(BASE_URL + '/enrollment-count?_=' + Date.now())
    .then(r => r.json())
    .then(data => {
      const total = parseInt(data.total_enrolled) || 0;
      animateCounter(total);
    })
    .catch(() => {});
}

function animateCounter(target) {
  const el = document.getElementById('enrollCounter');
  if (!el || target === 0) return;
  let current = parseInt(el.textContent) || 0;
  if (current === target) return;
  const step  = Math.max(1, Math.ceil(Math.abs(target - current) / 60));
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    el.textContent = current;
    if (current >= target) clearInterval(timer);
  }, 30);
}

// ===== CHECK EMAIL =====
function checkEmail() {
  const email   = (document.getElementById('emailInput').value || '').trim();
  const errDiv  = document.getElementById('emailError');
  const btn     = document.getElementById('checkBtn');
  const btnText = document.getElementById('btnText');
  const spinner = document.getElementById('btnSpinner');

  errDiv.style.display = 'none';

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errDiv.textContent   = '⚠ Please enter a valid email address.';
    errDiv.style.display = 'block';
    return;
  }

  btnText.style.display = 'none';
  spinner.style.display = 'inline-block';
  btn.disabled          = true;

  fetch(BASE_URL + '/check-email', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ email })
  })
    .then(r => r.json())
    .then(data => {
      btnText.style.display = 'inline';
      spinner.style.display = 'none';
      btn.disabled          = false;

      if (data.status === 'found') {
        currentIntern    = data.intern;
        currentBatchInfo = data.batch_info || null;
        // Sync globals used by index.html inline script
        window._currentIntern    = currentIntern;
        window._currentBatchInfo = currentBatchInfo;
        showResult(data.intern, data.batch_info);

      } else if (data.status === 'already_enrolled') {
        const statusMap = {
          'Accepted':             { color: '#4caf50', icon: 'fa-check-circle', label: 'Accepted — Offer Letter Sent' },
          'Rejected':             { color: '#ff6b6b', icon: 'fa-times-circle', label: 'Rejected — Please Re-submit'  },
          'Pending Verification': { color: '#ffb020', icon: 'fa-clock',        label: 'Pending Verification'         },
        };
        const ps    = data.payment_status || 'Pending Verification';
        const sInfo = statusMap[ps] || statusMap['Pending Verification'];

        const msgEl = document.getElementById('enrolled-msg');
        if (msgEl) {
          msgEl.innerHTML =
            'Hi <strong>' + (data.name || 'there') + '</strong>, you have already submitted your enrollment.';
        }

        const psEl = document.getElementById('enrolled-payment-status');
        const box  = document.getElementById('enrolled-status-box');
        if (psEl) {
          psEl.innerHTML   = `<i class="fas ${sInfo.icon}"></i>&nbsp; ${sInfo.label}`;
          psEl.style.color = sInfo.color;
        }
        if (box) {
          box.style.borderColor = sInfo.color;
        }

        document.getElementById('enrolledModal').style.display = 'flex';
        document.body.style.overflow = 'hidden';

      } else {
        errDiv.innerHTML     = '<i class="fas fa-times-circle"></i> ' + (data.message || 'Email not found.');
        errDiv.style.display = 'block';
      }
    })
    .catch(() => {
      btnText.style.display = 'inline';
      spinner.style.display = 'none';
      btn.disabled          = false;
      errDiv.textContent    = 'Network error. Please try again.';
      errDiv.style.display  = 'block';
    });
}

// ===== SHOW RESULT =====
function showResult(intern, batchInfo) {
  // Hide hero, show result
  const heroEl = document.getElementById('hero-section');
  const resEl  = document.getElementById('result-section');
  if (heroEl) heroEl.style.display = 'none';
  if (resEl)  { resEl.style.display = 'block'; resEl.scrollIntoView({ behavior: 'smooth' }); }

  // Profile
  const firstName = (intern.name || '').split(' ')[0];
  setText('congrats-name',    firstName + '!');
  setText('intern-name',      intern.name    || '—');
  setText('intern-phone',     intern.phone   || 'Not provided');
  setText('intern-email',     intern.email   || '—');
  setText('intern-college',   intern.college || 'Not provided');
  setText('intern-domain',    intern.domain  || '—');

  const initials = (intern.name || 'DB')
    .split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
  setText('profile-avatar', initials);

  // Batch info
  if (batchInfo) {
    const b           = batchInfo;
    const joinDisplay = b.joining_date || b.default_date || '—';
    const labelText   = b.label || (b.batch == 2 ? 'Batch 2 — June 2026' : 'Batch 1 — May 2026');

    setText('join-date-display',  ' ' + joinDisplay);
    setText('batch-tag-display',  labelText);
    setText('offer-batch-date',   joinDisplay);
    setText('success-batch-date', joinDisplay);

    const batchLabelEl = document.getElementById('batch-label-text');
    if (batchLabelEl) batchLabelEl.textContent = labelText + ' | India\'s #1 AI-Powered Internship Program';

    // Date picker
    const picker = document.getElementById('joining-date-picker');
    if (picker) {
      if (b.min_date)     picker.min   = b.min_date;
      if (b.max_date)     picker.max   = b.max_date;
      if (b.default_date) picker.value = b.default_date;
    }

    // Seats info
    const seatsEl = document.getElementById('seats-remaining-text');
    const batchEl = document.getElementById('batch-assigned-text');
    const dr = b.domain_remaining !== undefined ? b.domain_remaining : b.seats_remaining;
    if (seatsEl) {
      if (dr <= 0) {
        seatsEl.textContent = '⚠ Batch 1 is full for your domain — you are in Batch 2 (June 2026)';
        seatsEl.style.color = '#ff6b6b';
      } else if (dr <= 5) {
        seatsEl.textContent = `🔥 Only ${dr} seats left in your domain — enroll immediately!`;
        seatsEl.style.color = '#ffb020';
      } else {
        seatsEl.textContent = `✅ ${dr} seats available in ${labelText}`;
        seatsEl.style.color = '#4caf50';
      }
    }
    if (batchEl) batchEl.textContent = labelText;

    // Batch 2 warning banner
    if (b.batch === 2) {
      const b2w = document.getElementById('batch2-warning');
      if (b2w) b2w.style.display = 'block';
    }

    // Email sent notice
    if (b.email_sent || batchInfo.email_sent) {
      const notice = document.getElementById('email-sent-notice');
      if (notice) notice.style.display = 'block';
      const remEl = document.getElementById('emails-remaining-text');
      const rem   = b.emails_remaining;
      if (remEl && rem !== undefined) {
        remEl.textContent = `(${rem} resend${rem !== 1 ? 's' : ''} remaining)`;
      }
    }
  }

  triggerConfetti();
}

// ===== CONFETTI =====
function triggerConfetti() {
  const colors = ['#e2b96f','#f5d78e','#c9922a','#fff','#4caf50','#2196F3'];
  const banner = document.querySelector('.congrats-banner');
  if (!banner) return;
  for (let i = 0; i < 60; i++) {
    setTimeout(() => {
      const c    = document.createElement('div');
      const size = Math.random() * 8 + 4;
      c.style.cssText = `
        position:absolute;width:${size}px;height:${size}px;
        background:${colors[Math.floor(Math.random() * colors.length)]};
        left:${Math.random()*100}%;top:-10px;
        border-radius:${Math.random() > 0.5 ? '50%' : '2px'};
        animation:confetti-fall ${Math.random()*2+1.5}s linear forwards;
        pointer-events:none;z-index:5;
        transform:rotate(${Math.random()*360}deg);
      `;
      banner.appendChild(c);
      setTimeout(() => c.remove(), 3500);
    }, i * 50);
  }
}

// ===== ENROLLMENT FORM =====
function openEnrollmentForm() {
  const intern = currentIntern || window._currentIntern;
  const b      = currentBatchInfo || window._currentBatchInfo;
  if (!intern) return;

  setValue('form-name',    intern.name    || '');
  setValue('form-email',   intern.email   || '');
  setValue('form-domain',  intern.domain  || '');
  setValue('form-phone',   intern.phone   || '');
  setValue('form-college', intern.college || '');

  if (b) {
    const picker = document.getElementById('joining-date-picker');
    if (picker) {
      if (b.min_date)     picker.min   = b.min_date;
      if (b.max_date)     picker.max   = b.max_date;
      if (b.default_date) picker.value = b.default_date;
    }
  }

  document.getElementById('enrollModal').style.display = 'flex';
  document.body.style.overflow = 'hidden';
}

function closeModal() {
  const m = document.getElementById('enrollModal');
  if (m) m.style.display = 'none';
  document.body.style.overflow = '';
}

function closeSuccessModal() {
  const m = document.getElementById('successModal');
  if (m) m.style.display = 'none';
  document.body.style.overflow = '';
  location.reload();
}

// ===== FILE SELECT =====
function handleFileSelect(input) {
  if (input.files && input.files[0]) {
    const file    = input.files[0];
    const maxSize = 5 * 1024 * 1024;
    if (file.size > maxSize) {
      alert('File too large. Please upload a file smaller than 5MB.');
      if (input.value !== undefined) input.value = '';
      return;
    }
    const nameEl    = document.getElementById('file-name-display');
    const previewEl = document.getElementById('file-preview');
    const dropEl    = document.getElementById('dropArea');
    if (nameEl)    nameEl.textContent        = file.name;
    if (previewEl) previewEl.style.display   = 'flex';
    if (dropEl)    dropEl.classList.add('has-file');
  }
}

// ===== COPY UPI =====
function copyUPI() {
  const upiEl = document.getElementById('upi-text');
  if (!upiEl) return;
  const upiId = upiEl.textContent.trim();
  navigator.clipboard.writeText(upiId).then(() => {
    const container = document.querySelector('.upi-id');
    if (!container) { showToast('UPI ID copied! ✅'); return; }
    const orig = container.innerHTML;
    container.innerHTML = '<i class="fas fa-check" style="color:#4caf50;"></i>&nbsp;<span style="color:#4caf50;">Copied!</span>';
    setTimeout(() => { container.innerHTML = orig; }, 2000);
  }).catch(() => showToast('UPI ID: ' + upiId));
}

// ===== FAQ TOGGLE =====
function toggleFAQ(btn) {
  const item   = btn.parentElement;
  const isOpen = item.classList.contains('open');
  document.querySelectorAll('.faq-item.open').forEach(i => i.classList.remove('open'));
  if (!isOpen) item.classList.add('open');
}

// ===== TOAST =====
function showToast(msg, color) {
  let t = document.getElementById('_globalToast');
  if (!t) {
    t    = document.createElement('div');
    t.id = '_globalToast';
    t.style.cssText =
      'position:fixed;bottom:24px;right:24px;background:#0f1622;' +
      'border:1px solid rgba(226,185,111,.3);color:#e2b96f;' +
      'padding:12px 20px;border-radius:12px;font-size:13px;font-weight:600;' +
      'z-index:9999;box-shadow:0 8px 24px rgba(0,0,0,.4);' +
      'transition:opacity .3s;font-family:Inter,sans-serif;';
    document.body.appendChild(t);
  }
  t.textContent   = msg;
  t.style.color   = color || '#e2b96f';
  t.style.display = 'block';
  t.style.opacity = '1';
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => {
    t.style.opacity = '0';
    setTimeout(() => { t.style.display = 'none'; }, 300);
  }, 2800);
}

// ===== HELPERS =====
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function setValue(id, val) {
  const el = document.getElementById(id);
  if (el) el.value = val;
}