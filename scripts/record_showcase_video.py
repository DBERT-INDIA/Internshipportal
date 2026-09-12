"""
DBERT Internship Portal - Automated Showcase & Video Recording Script
Powered by Playwright (Python)

This script automates and records a high-definition video walkthrough
of all major UI/UX changes and backend features introduced in v2.0-v2.3:
  1. Modern Hero Section, GSAP entrance sequences, and student photography.
  2. Lenis hardware-accelerated smooth scrolling & spotlight card micro-interactions.
  3. 6-card "Browse by Domain" grid with slug routing and "Skip the wait" banner.
  4. Redesigned Auth modal with obsidian/gold styling and dual-identifier Sign In (Phone & Email).
  5. 3-step registration flow with +91 country phone prefix and real-time email existence check.
  6. Verified database-backed Forgot Password flow.
  7. Resilient Student Portal (/portal) dashboard with status sequence and tab navigation.
  8. Admin Portal (/admin) user table deduplication and clean logout session flushing.

Run:
  python scripts/record_showcase_video.py
"""

import os
import sys
import time
import subprocess
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

BASE_URL = os.environ.get("PORTAL_URL", "http://127.0.0.1:5000")
OUTPUT_DIR = Path("artifacts/videos")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def is_server_running(url, timeout=2):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HealthCheck"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 302, 401, 403, 404)
    except Exception:
        return False

def ensure_server():
    if is_server_running(BASE_URL):
        print(f"[+] Server is already active at {BASE_URL}")
        return None
    
    print(f"[*] Starting local Flask server on {BASE_URL}...")
    proc = subprocess.Popen(
        [sys.executable, "app.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=Path(__file__).resolve().parent.parent
    )
    
    # Wait for server to accept connections
    for _ in range(30):
        time.sleep(0.5)
        if is_server_running(BASE_URL):
            print(f"[+] Server successfully started (PID {proc.pid})")
            return proc
            
    print("[-] Failed to start server in 15 seconds.")
    sys.exit(1)

def inject_overlay_hud(page):
    """Inject a sleek floating HUD overlay to display subtitles for each featured change."""
    hud_script = """
    (() => {
        if (document.getElementById('showcase-hud')) return;
        const hud = document.createElement('div');
        hud.id = 'showcase-hud';
        hud.style.position = 'fixed';
        hud.style.top = '24px';
        hud.style.left = '50%';
        hud.style.transform = 'translateX(-50%)';
        hud.style.zIndex = '999999';
        hud.style.display = 'flex';
        hud.style.alignItems = 'center';
        hud.style.gap = '12px';
        hud.style.padding = '10px 22px';
        hud.style.background = 'rgba(14, 17, 26, 0.88)';
        hud.style.backdropFilter = 'blur(16px)';
        hud.style.webkitBackdropFilter = 'blur(16px)';
        hud.style.border = '1px solid rgba(212, 154, 55, 0.4)';
        hud.style.borderRadius = '999px';
        hud.style.boxShadow = '0 12px 36px rgba(0, 0, 0, 0.45), 0 0 15px rgba(212, 154, 55, 0.2)';
        hud.style.color = '#FFFFFF';
        hud.style.fontFamily = 'Plus Jakarta Sans, Inter, sans-serif';
        hud.style.fontSize = '14px';
        hud.style.fontWeight = '600';
        hud.style.pointerEvents = 'none';
        hud.style.transition = 'all 0.3s cubic-bezier(0.16, 1, 0.3, 1)';
        
        hud.innerHTML = `
            <span id="hud-badge" style="background:#D49A37; color:#000000; font-size:11px; font-weight:800; padding:3px 8px; border-radius:999px; text-transform:uppercase; letter-spacing:0.05em;">SHOWCASE</span>
            <span id="hud-title" style="color:#F1F5F9; font-weight:700;">Initializing Walkthrough...</span>
        `;
        document.body.appendChild(hud);
        
        window.setHudTitle = (badge, title) => {
            const b = document.getElementById('hud-badge');
            const t = document.getElementById('hud-title');
            if (b) b.textContent = badge;
            if (t) t.textContent = title;
        };
    })();
    """
    page.evaluate(hud_script)

def set_hud(page, badge, title):
    try:
        page.evaluate(f"window.setHudTitle({repr(badge)}, {repr(title)});")
    except Exception:
        pass

def smooth_scroll(page, y_target, steps=25, delay=0.03):
    current_y = page.evaluate("window.scrollY")
    diff = y_target - current_y
    for i in range(1, steps + 1):
        progress = i / steps
        # Quad ease out
        ease = 1 - (1 - progress) * (1 - progress)
        pos = current_y + (diff * ease)
        page.evaluate(f"window.scrollTo(0, {pos})")
        time.sleep(delay)

def record_walkthrough():
    server_proc = ensure_server()
    
    print("\n🎬 Starting Playwright video capture session...")
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--disable-gpu-rasterization",
                "--no-sandbox",
                "--disable-setuid-sandbox"
            ]
        )
        
        # 1920x1080 Full HD video recording configuration
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            device_scale_factor=1,
            record_video_dir=str(OUTPUT_DIR),
            record_video_size={"width": 1920, "height": 1080}
        )
        
        page = context.new_page()
        
        try:
            # ─────────────────────────────────────────────────────────────
            # SCENE 1: MODERN HOMEPAGE HERO & ENTRANCE ANIMATIONS
            # ─────────────────────────────────────────────────────────────
            print("[Scene 1/8] Loading Homepage & Modern Hero...")
            page.goto(BASE_URL, wait_until="networkidle")
            page.wait_for_timeout(1000)
            inject_overlay_hud(page)
            set_hud(page, "HERO & MOTION", "Modern Hero Section, GSAP Animations & Student Photography")
            
            # Hover around floating metric badges
            page.wait_for_timeout(1500)
            page.mouse.move(960, 540)
            page.wait_for_timeout(1000)
            page.mouse.move(1400, 350)
            page.wait_for_timeout(1500)
            
            # ─────────────────────────────────────────────────────────────
            # SCENE 2: LENIS SMOOTH SCROLLING & SPOTLIGHT CARDS
            # ─────────────────────────────────────────────────────────────
            print("[Scene 2/8] Showcasing Lenis Scrolling & Spotlight Domains...")
            set_hud(page, "INTERACTIONS", "Lenis Inertia Smooth Scroll & Spotlight Domain Cards")
            smooth_scroll(page, 750, steps=30, delay=0.03)
            page.wait_for_timeout(1000)
            
            # Hover across domain cards to trigger dynamic Spotlight illumination
            cards = page.locator(".spotlight-card, .domain-card")
            card_count = min(cards.count(), 4)
            for i in range(card_count):
                box = cards.nth(i).bounding_box()
                if box:
                    page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
                    page.wait_for_timeout(600)
            
            # ─────────────────────────────────────────────────────────────
            # SCENE 3: PAID PROGRAM BANNER & BENEFITS GRID
            # ─────────────────────────────────────────────────────────────
            print("[Scene 3/8] Showcasing Paid Program & Harmonized Footer...")
            set_hud(page, "PAID PROGRAM", "Fast-Track Paid Program Banner, Perks & WCAG AA Contrast")
            smooth_scroll(page, 1550, steps=30, delay=0.03)
            page.wait_for_timeout(1800)
            
            # Scroll to footer
            set_hud(page, "THEME SYSTEM", "Harmonized Crisp White Footer with Registered MSME Badge")
            smooth_scroll(page, 2700, steps=35, delay=0.03)
            page.wait_for_timeout(1500)
            
            # Scroll back to top
            smooth_scroll(page, 0, steps=25, delay=0.02)
            page.wait_for_timeout(1000)
            
            # ─────────────────────────────────────────────────────────────
            # SCENE 4: REDESIGNED AUTH MODAL & DUAL IDENTIFIER SIGN IN
            # ─────────────────────────────────────────────────────────────
            print("[Scene 4/8] Demonstrating Auth Modal & Dual Identifier...")
            set_hud(page, "AUTH SYSTEM", "Redesigned Auth Modal: Sign In with 10-Digit Mobile or Email")
            
            # Click Sign In CTA
            page.locator("a[data-act-click='showAuthOverlay'], button[data-act-click='showAuthOverlay']").first.click()
            page.wait_for_timeout(1200)
            
            # Input registered phone number (dual identifier demonstration)
            phone_input = page.locator("#si_email")
            if phone_input.is_visible():
                phone_input.fill("9998887776")
                page.wait_for_timeout(800)
                page.locator("#siEmailBtn").click()
                page.wait_for_timeout(1200)
                
                # Show password step resolved from phone
                pw_input = page.locator("#si_password")
                if pw_input.is_visible():
                    set_hud(page, "AUTH VERIFIED", "Mobile Number Recognized -> Password Step Unlocked")
                    pw_input.fill("TestUser@2026")
                    page.wait_for_timeout(1200)
            
            # ─────────────────────────────────────────────────────────────
            # SCENE 5: 3-STEP SIGN UP & PHONE INPUT PREFIX
            # ─────────────────────────────────────────────────────────────
            print("[Scene 5/8] Demonstrating 3-Step Sign Up & Real-Time Blur Check...")
            set_hud(page, "SIGN UP FLOW", "3-Step Registration Modal with +91 Country Phone Input")
            
            page.locator("#tabSignup").click()
            page.wait_for_timeout(1200)
            
            # Show email collision blur check
            email_field = page.locator("#su_email")
            if email_field.is_visible():
                email_field.fill("testuser@dbert.online")
                # Trigger blur check
                email_field.blur()
                page.wait_for_timeout(1200)
                set_hud(page, "VALIDATION", "Real-Time Email Collision Check -> Prompts Direct Sign In")
                page.wait_for_timeout(1500)
            
            # ─────────────────────────────────────────────────────────────
            # SCENE 6: FORGOT PASSWORD DATABASE VERIFICATION
            # ─────────────────────────────────────────────────────────────
            print("[Scene 6/8] Demonstrating Forgot Password Flow...")
            set_hud(page, "FORGOT PASSWORD", "Database-Backed Password Reset with Immediate Feedback")
            
            # Open Forgot Password modal directly
            page.evaluate("openForgotModal()")
            page.wait_for_timeout(1000)
            
            forgot_input = page.locator("#fp_email")
            if forgot_input.is_visible():
                # Non-existent email test
                forgot_input.fill("unregistered_student@example.com")
                page.wait_for_timeout(600)
                page.locator("#forgotBtn").click()
                page.wait_for_timeout(1400)
                set_hud(page, "SECURITY", "404 Error: Prevents Silent Failures for Non-Existent Accounts")
                page.wait_for_timeout(1500)
                
                # Registered email test
                forgot_input.fill("testuser@dbert.online")
                page.wait_for_timeout(600)
                page.locator("#forgotBtn").click()
                page.wait_for_timeout(1400)
                set_hud(page, "RESET SENT", "Cryptographic Reset Token Generated with Direct Action URL")
                page.wait_for_timeout(1800)
                
                # Close forgot modal
                page.evaluate("closeForgotModal()")
                page.wait_for_timeout(800)
            
            # ─────────────────────────────────────────────────────────────
            # SCENE 7: STUDENT PORTAL (/portal) DASHBOARD
            # ─────────────────────────────────────────────────────────────
            print("[Scene 7/8] Demonstrating Student Portal (/portal)...")
            set_hud(page, "STUDENT PORTAL", "Resilient Student Portal: Status Sequence, Tabs & Zero Blank Screen")
            
            # Log in to access portal
            page.goto(f"{BASE_URL}/#signin")
            page.wait_for_timeout(1200)
            inject_overlay_hud(page)
            set_hud(page, "PORTAL AUTH", "Authenticating Intern Session...")
            
            si_input = page.locator("#si_email")
            if si_input.is_visible():
                si_input.fill("testuser@dbert.online")
                page.locator("#siEmailBtn").click()
                page.wait_for_timeout(800)
                page.locator("#si_password").fill("TestUser@2026")
                page.locator("#signinBtn").click()
                page.wait_for_timeout(2000)
            
            # Check portal dashboard
            page.goto(f"{BASE_URL}/portal")
            page.wait_for_timeout(1500)
            inject_overlay_hud(page)
            set_hud(page, "PORTAL DASHBOARD", "Canonical 'Accepted' Application Timeline & Active Tab Panel")
            page.wait_for_timeout(2000)
            
            # Switch tabs to verify stability
            my_apps_tab = page.locator('.nav-item[data-tab="myapplications"]')
            if my_apps_tab.is_visible():
                my_apps_tab.click()
                page.wait_for_timeout(1200)
            overview_tab = page.locator('.nav-item[data-tab="overview"]')
            if overview_tab.is_visible():
                overview_tab.click()
                page.wait_for_timeout(1200)
            
            # ─────────────────────────────────────────────────────────────
            # SCENE 8: ADMIN USER MANAGEMENT & CLEAN LOGOUT
            # ─────────────────────────────────────────────────────────────
            print("[Scene 8/8] Demonstrating Admin Dashboard & Clean Logout...")
            set_hud(page, "ADMIN PORTAL", "Admin Portal: Users Deduplication, Cascade Delete & Clean Logout")
            
            # Navigate to Admin Login
            page.goto(f"{BASE_URL}/admin-login")
            page.wait_for_timeout(1000)
            inject_overlay_hud(page)
            set_hud(page, "ADMIN AUTH", "Logging into Staff Admin Dashboard...")
            
            admin_email = page.locator("#username")
            admin_pw = page.locator("#password")
            if admin_email.is_visible() and admin_pw.is_visible():
                admin_email.fill("admin@dbert.online")
                admin_pw.fill("AdminPassword@2026")
                page.locator("#loginBtn").click()
                page.wait_for_timeout(2000)
            
            if "/admin" in page.url:
                inject_overlay_hud(page)
                set_hud(page, "ADMIN DEDUPLICATION", "Users Tab: 1 Unique Row Per User (Cartesian Product Fixed)")
                users_tab = page.locator('.nav-item[data-tab="users"]')
                if users_tab.is_visible():
                    users_tab.click()
                page.wait_for_timeout(2200)
                
                # Demonstrate Clean Admin Logout
                set_hud(page, "ADMIN LOGOUT", "Flushing Server Session & Client Storage -> Clean Redirect")
                logout_btn = page.locator("button[data-act-click='doLogout']").first
                if logout_btn.is_visible():
                    logout_btn.click()
                    page.wait_for_timeout(2000)
            
            # Return to Home for closing shot
            page.goto(BASE_URL)
            page.wait_for_timeout(1000)
            inject_overlay_hud(page)
            set_hud(page, "COMPLETE", "DBERT Internship Portal v2.3.0 Walkthrough Complete")
            page.wait_for_timeout(2500)

        finally:
            print("[*] Finalizing and encoding recorded video...")
            page.close()
            context.close()
            browser.close()
            
            if server_proc:
                print("[*] Terminating temporary Flask server...")
                server_proc.terminate()

    # Locate generated video file
    video_files = list(OUTPUT_DIR.glob("*.webm"))
    if video_files:
        # Sort by creation time (latest)
        latest_video = max(video_files, key=os.path.getctime)
        named_video = OUTPUT_DIR / "dbert_v2.3.0_showcase.webm"
        if named_video.exists():
            named_video.unlink()
        latest_video.rename(named_video)
        print(f"\n=======================================================")
        print(f"🎉 VIDEO RECORDED SUCCESSFULLY!")
        print(f"📍 File Path: {named_video.resolve()}")
        print(f"📊 Size: {named_video.stat().st_size / (1024 * 1024):.2f} MB")
        print(f"▶️ Play with: VLC, Chrome, Edge, or Firefox")
        print(f"=======================================================\n")
        return named_video
    else:
        print("[-] No video was saved.")
        return None

if __name__ == "__main__":
    record_walkthrough()
