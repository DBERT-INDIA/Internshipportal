# Changelog

All notable changes to the DBERT Internship Portal project are documented in this file.

## [2.3.0] - 2026-09-12

### Added
- **Restored Phone Number Input in Sign Up Form**:
  - Restored phone number input field in Step 1 of Sign Up modal with `+91` country prefix badge.
  - Fully harmonized styling with the dark charcoal & gold theme (`.phone-input-wrap`, `.phone-prefix`, focus states with golden border glow `#D49A37`).
  - Added dual identifier support in Sign In: users can authenticate via either their registered Email or 10-digit Phone Number (`check_email` and `intern_login`).
- **Provisioned Dedicated Test Accounts**:
  - **Admin Account**: `admin@dbert.online` (Staff account with full privileges).
  - **Test User Account**: `testuser@dbert.online` (Phone: `9998887776`, enrolled intern account).

### Fixed
- **Admin Logout Functionality**:
  - Resolved issue where logging out of `/admin` redirected back to `/admin` due to persistent Flask session cookie containing `admin_id`.
  - Updated `_clear_session_cookie()` in `app.py` to invoke `session.clear()`, completely flushing the Flask session.
  - Updated `admin_logout` endpoint to support both `GET` and `POST`, and updated `templates/admin.html` `doLogout()` to purge `sessionStorage` and `localStorage` before redirecting to `/admin-login`.
- **User Dashboard (`/portal`) Blank Screen and Network Error**:
  - **JS ReferenceError**: Declared missing `ALL_DOMAINS` and `DOMAIN_EMOJIS` constants in `templates/portal.html` that previously broke `populateApplyAnother()` and `renderOverview()`, halting dashboard initialization.
  - **CSS Specificity Override**: Fixed `dbert-theme.css` where high-specificity selector `body.portal .panel { display: none; }` overrode `.panel.active`, keeping active panels invisible. Added `body.portal .panel.active { display: block !important; }`.
- **Admin User Deletion & Cascade Purge**:
  - **Resolved 500 Crash on Bulk Delete**: Removed call to non-existent function `log_audit_event()` that crashed `/admin/users/bulk-delete` with a `NameError` and caused database rollbacks.
  - **Full Cascading Deletion**: Replaced incomplete soft-delete (`UPDATE is_active=0`) with full transactional cascade deletion across all associated user records: applications, enrollments, attendance, sessions, device profiles, tutor progress, password resets, interviews, tokens, certificates, and submissions.
  - **Response Payload Alignment**: Fixed JSON response to return `deleted: count` (instead of `deactivated`), enabling the UI toast to display accurate confirmation (`"Deleted 1 user."`).
- **Admin Users Tab Row Deduplication (Image 1 Fix)**:
  - Fixed Cartesian product bug in `admin_users()` in `app.py` where a raw `LEFT JOIN device_profiles dp ON dp.email = ia.email` caused users with multiple device profiles to duplicate across multiple rows (e.g., repeating the same user 4 times).
  - Aggregated device profiles via `LEFT JOIN (SELECT email, MAX(intent_score) AS intent_score FROM device_profiles WHERE email IS NOT NULL AND email != '' GROUP BY email) dp ON LOWER(dp.email) = LOWER(ia.email)`, guaranteeing exactly one unique row per registered user.

## [2.2.0] - 2026-09-12

### Changed & Overhauled
- **Footer Theme Harmonization (Image 1)**:
  - Transitioned the footer from mismatched dark navy block with empty margins to seamlessly integrate with the clean modern page theme: crisp white surface (`#FFFFFF`), subtle border-top (`1px solid #E2E8F0`), high-contrast dark headings (`#0F172A`), legible slate links (`#475569` with hover `#0F172A`), and clear social icons.

- **Auth Modal Redesign Matching Images 2 & 3**:
  - Restyled `#authOverlay` to match the exact dark obsidian & amber aesthetic shown in Images 2 and 3.
  - Charcoal card container (`#0E111A`) with subtle border (`rgba(255,255,255,0.08)`), pill toggle tabs (`#141724`) with golden/amber active tab (`#D49A37`, `#000000` text).
  - **Sign In Tab (Image 2)**: Centered uppercase `EMAIL` label, dark input field (`#141824`), and golden pill `-> Continue` CTA button.
  - **Sign Up Tab (Image 3)**: 3-step numbered progress indicators (golden circle 1 with `Account` label), `CREATE YOUR ACCOUNT` header, two-column form grid with uppercase labels, custom checkboxes with golden legal links, and golden `+ Create account & continue` CTA button.

- **Auth Modal Alignment & Layout Proportioning (Fix Cut-off / Width Mismatch)**:
  - Unified widths of `.auth-tabs` and `.auth-card` to match identically (`100%` of `.auth-wrapper` at `max-width: 470px`), resolving the mismatched pill tab overflow.
  - Compacted vertical padding and spacing across `.auth-card`, step indicators, field grids, and submit buttons.
  - Enabled smooth flex-centering with `margin: auto` inside `#authOverlay` to prevent bottom buttons and footer captions from clipping on standard laptop viewports.
- **Forgot Password Flow & Database Verification (Image 4)**:
  - Updated `/forgot-password` in `app.py` to query the database and explicitly verify whether the email exists.
  - Non-existent emails now return a clear error: `"No account found with this email in our database. Please check your email or Sign Up."`.
  - Registered emails generate a secure reset token, attempt email dispatch, log the reset URL in server logs, and in development mode provide a direct reset link so testing is never blocked.
  - Styled the forgot password modal to match Image 4 with high-contrast green success alerts.

- **Account Creation Email Existence Check**:
  - Integrated real-time blur check on the signup email field to notify users immediately if their email already exists in the database.
  - Updated form submission error handling to show an inline warning with an instant `"Sign in instead"` link rather than jarring tab shifts.

- **Text Contrast & Visibility Across Application**:
  - Upgraded global CSS text ramp variables: `--tx-body` (`#1E293B`) and `--tx-muted` (`#475569`).
  - Improved readability of section subtitles, domain cards, benefits cards, FAQ answers, badges, and form placeholders to ensure compliance with WCAG AA contrast standards.

## [2.1.0] - 2026-09-12

### Changed & Overhauled
- **Theme Overhaul to Match Image 2 Aesthetic Across Entire Application**:
  - Transitioned global palette from dark obsidian to the clean, modern light aesthetic shown in Image 2: Slate canvas (`#F8FAFC`), crisp white surface cards (`#FFFFFF`), deep navy headings/buttons (`#0F172A`), royal blue brand accent (`#2563EB`), and muted slate labels (`#64748B`).
  - Implemented 2-column hero with photorealistic student photography, floating interactive badges ("Build Learn Grow", "10K+ Students growing with DBERT"), and duration/mode pills.
  - Implemented 6-card "Browse by Domain" grid with soft pastel badges (AI, Data Analysis, Full Stack, Python Automation, Web Development, More Domains).
  - Implemented 2-column "Skip the wait with our Paid Program" banner with student photography, blue checkmark benefits, and primary CTA.
  - Implemented 4-card "Benefits & Perks" grid with pastel icons (Completion Certificate, LOR, Performance Stipend, Offer Letter).
  - Implemented 2-column FAQ accordion grid matching Image 2 layout.
  - Implemented dark navy modern footer (`#0B1220`) with MSME registration badge, links, social icons, and copyright.
  - Applied design tokens across all views (`portal.html`, `courses_catalog.html`, `tasks_list.html`, etc.) via global CSS root variables.

- **Scroll Performance & Lag Elimination**:
  - Eliminated virtual scroll-wheel interception and heavy ticker syncing that caused scroll lag on Windows platforms.
  - Restored native hardware-accelerated smooth scrolling (`scrollBehavior = 'smooth'`) with zero latency.
  - Wrapped interactive mousemove handlers in `requestAnimationFrame` to ensure 60/120fps fluid responsiveness.

- **Redesigned Auth Modal (Login / Sign Up)**:
  - Rebuilt `#authOverlay` with high-contrast centered card, frosted backdrop `rgba(15,23,42,0.7)`, pure white card `#FFFFFF`, rounded corners `24px`, and dark navy pill CTA button `#0F172A`.
  - Fixed field alignment, step transitions, and scrolling so that Step 1 (Account), Step 2 (Academics), Step 3 (Profile & Goals), and Sign In render cleanly without clipping or overflow issues.

## [2.0.0] - 2026-09-12

### Added
- **Modern Creative UI & Animation Stack**:
  - Integrated **Lenis** (`lenis.min.js`) for smooth, hardware-accelerated inertia scrolling.
  - Integrated **GSAP** & **ScrollTrigger** (`gsap.min.js`, `ScrollTrigger.min.js`) for staggered hero entrance animations and viewport reveal effects.
  - Added **React-Bits** inspired interactive UI components: spotlight cards (`.spotlight-card` with dynamic cursor tracking), magnetic action buttons (`.btn-magnetic`), and organic ambient aurora mesh (`.aurora-bg`).
  - Added modern design tokens in `dbert-theme.css` with cosmic obsidian canvas (`#07080E`), luminous glass panels (`#0E111D`), celestial amber accent (`#F59E0B`), and electric indigo/cyan accents.
- **Automated Verification Suite**:
  - Playwright test script validating Lenis, GSAP, CSS performance rules, authentication modal toggling, domain routing, and portal auth guarding.

### Fixed
- **Performance / Lag Elimination**:
  - Replaced CPU/GPU-taxing 90px CSS Gaussian blurs on large Aurora background elements with performant multi-stop CSS radial gradients, hardware compositing (`will-change: transform`, `transform: translate3d(0,0,0)`), and `contain: paint`.
  - Added `requestAnimationFrame` debouncing on cursor tracking events (`mousemove`) in `creative-ui.js` to prevent continuous DOM reflows and layout recalculations.
  - Tuned Lenis scroll duration to `0.65s` for instantaneous, crisp scroll responsiveness.
- **Auth Modal Visibility (Image 1)**:
  - Fixed CSS selector specificity conflict in `dbert-theme.css` where `body.home .auth-panel` (specificity `0,2,1`) had hidden the form inputs inside the `.active` panel.
  - Added `body.home .auth-panel.active { display: block !important; }` so that Sign In and 3-step Sign Up forms render completely with all form inputs.
- **Domain Cards 404 Error (Image 2)**:
  - Resolved issue in `app.py` where `/jobs/<slug>` and `/internships/<slug>` only matched city locations and returned 404 for domain slugs.
  - Added domain slug check against `DOMAIN_SLUGS` to redirect domain URLs cleanly to filtered search listings (`/jobs?domain=...`).
- **Portal Endless Spinner / Profile Error (Image 3)**:
  - Fixed issue where unauthenticated visitors navigating directly to `/portal` hit 401 on `/intern/me`, showing an error toast and stalling indefinitely on "Loading your portal...".
  - Added server-side session check in `portal_page()` in `app.py` and client-side 401 handler in `portal.html` to redirect unauthenticated visitors cleanly to `/#signin`.
