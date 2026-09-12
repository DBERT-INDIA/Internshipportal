# DBERT.online — SEO Content Plan (v1.0)

Plan-only document. Covers every route in the codebase. Nothing here is code — this is the content specification we execute against in the next step.

---

## Part 1 — Strategy foundations

### 1.1 The three keyword territories

Each vertical owns a distinct search territory. Pages never compete with each other for the same keyword (one primary keyword = one page, forever).

| Territory | Head terms (hard, long-game) | Winnable terms (target first) | Buyer intent |
|---|---|---|---|
| **Startups** | startup incubator, AI incubator | AI startup incubator India, equity-based incubation, technical co-founder as a service, startup incubator Delhi NCR | Founder evaluating incubation |
| **Enterprise/Products** | enterprise AI, document AI | self-hosted LLM chat for enterprise, document AI India, certificate verification API, AI hiring automation India, private LLM hosting India | Enterprise buyer with a specific need |
| **Learners** | AI course, internship | paid AI internship India, AI internship for students, AI course with placement guarantee India, python course with certificate India | Student/switcher choosing a program |

Learners is the highest-volume territory and should get content priority. Startups is lowest-volume but highest per-conversion value. Products sit between.

### 1.2 Site-wide rules (apply to every page)

1. **One primary keyword per page**, declared at the top of each page spec below. 2–4 secondary keywords woven naturally.
2. **Title tag**: ≤ 60 chars, primary keyword front-loaded, brand suffix `| DBERT` (template already exists in layout.tsx).
3. **Meta description**: 140–155 chars, contains primary keyword, ends with an action phrase.
4. **H1**: exactly one per page, contains the primary keyword or a close variant. (Current site: many H1s are slogans — all get rewritten.)
5. **H2s phrased as questions or search phrases** where natural — they feed "People Also Ask".
6. **Word count floors**: hub pages 900–1,400 · detail pages 600–1,000 · legal pages exempt.
7. **FAQ block** (5–8 Q&As) on every commercial page, with FAQPage schema.
8. **Internal links**: every page links up to its hub, sideways to 1–2 siblings, and down to its children. Anchor text = target page's keyword, never "click here".
9. **India signals** where relevant: ₹ pricing, Delhi NCR mentions, Indian examples — this is how we win geo-qualified terms.
10. **The v2 design voice carries into copy**: specific numbers, honest disclosures, provenance stories. Google's helpful-content system rewards exactly this; it doubles as our anti-AI-slop insurance.

### 1.3 Schema map

| Schema type | Applied to |
|---|---|
| Organization (exists) | site-wide — extend with `sameAs` social links, `founder` |
| BreadcrumbList | every page below the homepage |
| Service | /startups, all 7 /startups/services/*, /ai-solutions/consultation, /ai-solutions/llm-training/* |
| SoftwareApplication | all 5 product pages |
| Course | all 4 course pages + launchpad + accelerate (price, provider, courseMode, offers) |
| FAQPage | every page carrying an FAQ block |
| Article + author | every blog post |
| JobPosting | /about/careers (when roles are live) |
| Review/AggregateRating | portfolio case studies (only with real, verifiable reviews) |

---

## Part 2 — Page-by-page specifications

Format per page: **Primary KW** · Title · Meta · H1 · Outline · Links · Schema.

### 2.1 Core

#### `/` Homepage
- **Primary KW**: AI venture studio India
- **Title**: `AI Venture Studio India — Incubation, SaaS & AI Careers | DBERT`
- **Meta**: `DBERT is India's AI venture studio: equity-based startup incubation, enterprise AI products, and job-focused engineering programs. Built in Delhi.`
- **H1**: `The AI venture studio that writes the code` (keyword lives in intro paragraph + title; hero headline stays the approved brand line)
- **Outline**: hero (approved v2) → router → §01 incubation summary (150w) → §02 products summary (150w) → §03 ladder (from v2) → §04 case proof → founder's note → CTA. Add a 120-word "What is DBERT" prose block above the footer for crawlers (visible, not hidden).
- **Links**: down to all 3 hubs + /startups/register + /learners/launchpad.
- **Schema**: Organization (extended), WebSite + SearchAction.

#### `/pricing`
- **Primary KW**: DBERT pricing
- **Title**: `Pricing — Programs, Products & Incubation Terms | DBERT`
- **Meta**: `Transparent pricing for DBERT learner programs, enterprise products, and equity-based incubation. No hidden fees — see exactly what everything costs.`
- **Outline**: three pricing tables by audience → "how equity pricing works" explainer (300w) → FAQ (refunds, EMI, what's included).
- **Schema**: FAQPage, Offer inside Product/Course schemas on linked pages.

#### `/verify`
- **Primary KW**: verify DBERT certificate
- **Title**: `Verify a DBERT Certificate | DBERT`
- **Meta**: `Check the authenticity of any DBERT internship or course certificate in seconds. Enter the certificate ID to verify issue date, program, and holder.`
- **Outline**: verify tool → how verification works (200w, links Certificate API product page — a natural product-marketing loop) → FAQ.

#### `/privacy`, `/terms`, `/refund`
- Exempt from keyword targeting. Needs: last-updated date, plain-language summaries at top, internal links to /pricing and /about/contact. Refund page gets FAQPage schema (refund questions are searched: "dbert refund policy").

### 2.2 Startups vertical

#### `/startups` (hub)
- **Primary KW**: AI startup incubator India
- **Title**: `AI Startup Incubator in India — Equity-Based | DBERT`
- **Meta**: `DBERT incubates AI startups for equity — architecture, MVP development, and hiring from one engineering team in Delhi. See the model and apply.`
- **H1**: `An AI startup incubator that builds with you, for equity`
- **Outline** (1,200w): what equity-based incubation is → who it's for / not for (honest-disclosure block) → the 4-step process → what you get (links all 7 service pages) → portfolio strip → term-sheet transparency teaser → FAQ ("How much equity does DBERT take?", "Do I keep my codebase?", "Incubator vs accelerator?").
- **Links**: down to all services + register + portfolio; sideways to /ai-solutions (for post-incubation clients).
- **Schema**: Service, FAQPage, Breadcrumb.

#### `/startups/register`
- **Primary KW**: apply startup incubator India
- **Title**: `Apply for Incubation — Startup Application | DBERT`
- Short page: 250w of expectation-setting (response time, what we evaluate, the 1-in-5 acceptance stat) above the form. Reduce form anxiety = better conversion *and* dwell time.

#### `/startups/portfolio` (hub) + 4 company pages
- Hub KW: `DBERT portfolio startups` — index with one 80-word summary + one hard metric per company.
- **Each company page follows the Alkame v4 template** (already the best content on the site): problem → build log → cited results → contributor credits. Alkame targets `AI stock prediction startup India`-class terms; write equivalent keyword targets per company based on their domain (cognitive-solutions, digital-blaize, gayatri-ai) once domains are confirmed with you.
- Schema: Article + Organization (about the portfolio company).

#### `/startups/services/*` (7 pages: technical, equity, equity/term-sheets, funding, hiring, infrastructure, legal, investor-network)
Template (700w each): what the service covers → how it works inside incubation → what it costs (equity vs cash) → mini-case → FAQ → CTA to register.

| Page | Primary KW | Title (≤60c) |
|---|---|---|
| technical | technical co-founder as a service | `Technical Co-Founder as a Service | DBERT` |
| equity | equity-based startup services | `Equity-Based Startup Services — How It Works | DBERT` |
| equity/term-sheets | startup term sheet template India | `Startup Term Sheet Templates (India) — Free | DBERT` ★ |
| funding | startup funding support India | `Funding Readiness & Investor Prep | DBERT` |
| hiring | startup hiring India engineers | `Hire Vetted AI Engineers for Your Startup | DBERT` |
| infrastructure | startup cloud infrastructure setup | `Cloud & AI Infrastructure for Startups | DBERT` |
| legal | startup legal compliance India | `Startup Legal & IP Compliance Support | DBERT` |
| investor-network | angel investor network India AI | `AI Investor Network — Connect With Backers | DBERT` |

★ term-sheets is a **magnet page**: downloadable annotated templates earn backlinks. Give it 1,500w + downloadable assets.

### 2.3 AI Solutions / Products vertical

#### `/ai-solutions` (hub)
- **Primary KW**: enterprise AI solutions India
- **Title**: `Enterprise AI Solutions & Products — India | DBERT`
- **Meta**: `Production-ready enterprise AI from an Indian venture studio: self-hosted LLM chat, document AI, hiring automation, and custom LLM training.`
- Outline (1,000w): the "we run it before we sell it" thesis → product grid with provenance lines (from v2) → LLM training teaser → consultation CTA → FAQ ("Can this run in our VPC?", "Do you offer on-prem?").

#### 5 product pages — SoftwareApplication template (800w each)
Sections: what it does (plain language) → born-from story → how it works (architecture diagram) → security/compliance → integrations → pricing or "talk to us" → FAQ → related products.

| Page | Primary KW | Title |
|---|---|---|
| dbert-chat | self-hosted enterprise LLM chat | `Self-Hosted Enterprise LLM Chat — Your VPC | DBERT Chat` |
| document-ai | document AI OCR India | `Document AI — OCR & Contract Parsing at Scale | DBERT` |
| certificate-verification-api | certificate verification API | `Certificate Verification API — Issue & Verify | DBERT` |
| hiring-automation-suite | AI hiring automation software India | `AI Hiring Automation — Resume Parsing & Scoring | DBERT` |
| intern-management-system | intern management system software | `Intern Management System — Squads to Certificates | DBERT` |

#### LLM training cluster (`/ai-solutions/llm-training` + dbert-ai, pipeline, private-hosting)
- Hub KW: `custom LLM training services India`. Children: `fine-tune LLM on company data` (pipeline), `private LLM hosting India` (private-hosting), `DBERT AI model` (dbert-ai — brand page).
- private-hosting is the second **magnet page**: "Private LLM hosting in India — costs, hardware, and compliance" with real ₹ numbers. Almost nobody publishes Indian pricing; this ranks.

#### `/ai-solutions/consultation`
- **Primary KW**: AI consultation services India
- **Title**: `AI Consultation for Enterprises — Book a Session | DBERT`
- 500w: what a session covers, who runs it, outcomes → booking form → FAQ.

### 2.4 Learners vertical (priority territory)

#### `/learners` (hub)
- **Primary KW**: AI career programs India
- **Title**: `AI Career Programs — Zero to Hired, Four Rungs | DBERT`
- **Meta**: `A four-stage ladder from first Python script to paid fellowship and AI job placement. Real production code, verified certificates. Cohort 7 enrolling.`
- **H1**: `AI career programs built as a ladder, not a catalog`
- Outline (1,300w): the ladder (v2 horizontal component) → each rung expanded 150w with links → outcomes wall (real placement numbers) → how certificates verify (link /verify) → fees & EMI → FAQ ("Is the fellowship really paid?", "Can I skip Launchpad?", "Do you guarantee placement?" — answer honestly, it will rank).
- Schema: FAQPage, ItemList of Courses.

#### Program pages
| Page | Primary KW | Title | Notes |
|---|---|---|---|
| launchpad | AI course for beginners India | `AI & Python Course for Beginners — Launchpad | DBERT` | Course schema; syllabus week-by-week; "no prior coding" messaging |
| accelerate | AI engineering bootcamp India | `AI Engineering Program — RAG, Agents, Deployment | DBERT` | Course schema; project gallery is the differentiator |
| fellowship | paid AI internship India | `Paid AI Fellowship — Work on Real Client Systems | DBERT` | **Highest-volume keyword on the whole site.** 1,200w: stipend range, selection criteria, squad structure, verified-letter sample, alumni outcomes. Links to internship.dbert.online with proper anchor. |
| interview-prep | AI engineer interview preparation | `AI Engineer Interview Prep — Mock Interviews | DBERT` | 700w + free question-bank teaser (magnet) |
| jobs | AI jobs India freshers | `AI Jobs & Placement for Verified Builders | DBERT` | Placement stats table; alumni company logos (real only) |

#### 4 course pages — Course schema template (900w each)
Week-by-week syllabus → tools taught → capstone project described concretely → who teaches (real names + credentials, E-E-A-T requirement) → fee + EMI → certificate sample → FAQ → next cohort date.

| Page | Primary KW |
|---|---|
| ai-agent-development | AI agent development course |
| python-automation | Python automation course India |
| full-stack-development | full stack development course with placement |
| data-analytics | data analytics course India certificate |

### 2.5 Labs vertical

Labs is the **E-E-A-T engine** — it exists to prove expertise, which lifts rankings everywhere else.

| Page | Primary KW | Content need |
|---|---|---|
| /labs | DBERT Labs AI research | 600w: what Labs does, current research areas, links to publications |
| /labs/research | AI research India applied | Project index; each project 150w + status |
| /labs/publications | (brand) DBERT publications | Full citations, PDF links, abstract per paper — the Alkame paper first |
| /labs/opensource | DBERT open source | Repo cards w/ stars, contribution guide |
| /labs/collaborate | AI research collaboration India | 500w + form; targets academic partnerships |

### 2.6 About cluster

| Page | Primary KW | Content need |
|---|---|---|
| /about | about DBERT | 800w company story in founder-note voice; timeline; full legal name prominent (entity SEO) |
| /about/team | DBERT team | Real people, real photos, credential links — E-E-A-T critical; Person schema each |
| /about/credentials | DBERT credentials verified | Registrations, certifications, partnerships — with document proofs |
| /about/careers | careers at DBERT | JobPosting schema per live role; culture section in ticker-voice |
| /about/contact | contact DBERT | NAP consistency (name-address-phone identical everywhere), embedded map, response-time promise; LocalBusiness schema |

### 2.7 Blog — the growth engine

`/blog` hub KW: `AI engineering blog India`. Post templates: 1,200–2,000w, Article schema, author box linking /about/team, 3+ internal links, one original diagram each.

**First 12 posts, in priority order** (learner-intent first — highest volume):
1. How to get a paid AI internship in India (2026 guide) → links fellowship
2. AI engineer salary in India: fresher to 5 years → links jobs
3. RAG pipeline tutorial: build one from scratch → links accelerate
4. Python roadmap for non-CS students → links launchpad
5. How equity-based startup incubation works → links /startups
6. Cost of building an AI MVP in India (real numbers) → links technical
7. Self-hosted LLM vs ChatGPT Enterprise: compliance view → links dbert-chat
8. How we parsed 8,000 legal PDFs (Document AI story) → links document-ai
9. Conformal prediction for stock signals — Alkame deep-dive → links portfolio/alkame
10. Startup term sheets explained for Indian founders → links term-sheets
11. How to verify any online certificate (and spot fakes) → links /verify + certificate-api
12. Fine-tuning an LLM on company data: a practical walkthrough → links llm-training

Cadence: 2/month minimum. Each magnet page (term-sheets, private-hosting, interview question bank) gets one supporting post.

---

## Part 3 — Execution order (next step)

| Phase | Scope | Effort | Why first |
|---|---|---|---|
| **A** | Titles, metas, H1s for all ~70 pages per specs above | 1 pass | Highest ROI per hour; zero design risk |
| **B** | Homepage + 3 hub pages full rewrite | 4 pages | Hubs distribute authority to everything |
| **C** | Fellowship + 4 course pages + 5 product pages w/ schema | 10 pages | Revenue pages, Course/SoftwareApplication rich results |
| **D** | FAQ blocks + internal-link mesh site-wide; breadcrumbs | site-wide | Compounds A–C |
| **E** | Magnet pages (term-sheets, private-hosting) + first 4 blog posts | 6 pieces | Backlink + traffic engine |
| **F** | About/Labs E-E-A-T pass; remaining services; blog cadence | ongoing | Long-game authority |

## Part 4 — Open questions for you (needed before writing copy)

1. Real numbers to publish: fellows trained, placement count, stipend range, acceptance rate — I used the mockup's figures; confirm or correct each.
2. Portfolio companies' actual domains (cognitive-solutions, gayatri-ai, digital-blaize) so their keyword targets are real.
3. Which team members can be named with photos/credentials (E-E-A-T pages need real people).
4. Confirm testimonials: which are real and quotable with permission? Fabricated ones must not ship.
5. Course fees/EMI figures for Course schema `offers`.
6. Is internship.dbert.online staying a separate subdomain? (Affects whether fellowship content lives here or there — recommendation: overview + SEO content on main domain, application flow on subdomain.)
