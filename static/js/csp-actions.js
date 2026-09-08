/* ==========================================================================
   csp-actions.js — delegated event dispatch, so no page needs inline handlers.
   Build phase: 9  (DBERT_BUILD_SPEC.md §5.3 — closing the CSP 'unsafe-inline')

   WHY THIS EXISTS
   ---------------
   A nonce in `script-src` makes browsers IGNORE 'unsafe-inline' entirely. That
   is the point — injected <script> stops running — but it also kills every
   inline event handler, because a nonce is an attribute of a <script> element
   and cannot be applied to an onclick="" attribute. There were 276 of those in
   the markup and 24 more built at runtime inside innerHTML.

   So handlers moved out of executable markup and into data attributes:

       <button onclick="review(7,'verify')">        BEFORE
       <button data-act-click="review"              AFTER
               data-arg-click='[7, "verify"]'>

   This file installs ONE listener per event type on `document` and walks up
   from the target, which reproduces bubbling exactly. Nothing here evaluates a
   string as code — no eval, no new Function — so the CSP needs neither
   'unsafe-inline' nor 'unsafe-eval'. An injected data-act- attribute can only
   name a function the page already defines, with JSON-parsed arguments.

   ATTRIBUTES (per event, so one element can carry several)
   -------------------------------------------------------
     data-act-<evt>="fnName"     function to call; window[fnName], or a $builtin
     data-arg-<evt>='[...]'      JSON array of arguments (omit when there are none)
     data-prevent-<evt>          preventDefault() — the old `; return false;`
     data-ret-<evt>              the old `return fn(...)`: a false return
                                 preventDefaults. Only set where the original
                                 handler actually used `return`, because a
                                 handler without it ignored the return value.
     data-key-<evt>="Enter"      only fire when event.key matches — the old
                                 `if(event.key==='Enter') fn()`

   ARGUMENT TOKENS — the inline forms that referenced the DOM
   ---------------------------------------------------------
     "$el"        the element carrying the attribute   (old `this`)
     "$event"     the event object                     (old `event`)
     "$value"     el.value                             (old `this.value`)
     "$checked"   el.checked                           (old `this.checked`)

   `this` inside the called function is still the element, as it was inline.

   FOR MARKUP BUILT AT RUNTIME
   ---------------------------
     box.innerHTML = '<button ' + actAttr('click','openRow',[r.id]) + '>Open</button>';

   actAttr() JSON-encodes and HTML-escapes, so a DB value can never break out of
   the attribute — which is the same class of bug this codebase has hit three
   times (see RESUME_HERE.md).
   ========================================================================== */
(function () {
  'use strict';

  if (window.__dbertActionsInstalled) return;   // safe if loaded twice
  window.__dbertActionsInstalled = true;

  /* event name -> use capture phase?
     `error`, `focus` and `blur` do not bubble, so a document-level listener
     only sees them during capture. The rest are registered in the bubble
     phase, which is where an inline handler used to run. */
  var EVENTS = {
    click: false, change: false, input: false, submit: false,
    keypress: false, keydown: false, keyup: false,
    copy: false, paste: false, cut: false,
    error: true, focus: true, blur: true
  };

  /* Small DOM operations that used to sit inline as one-liners. Kept here
     rather than added to every page as near-duplicate functions. `this` is the
     element carrying the attribute, matching inline semantics. */
  var BUILTINS = {
    '$hide':         function () { this.style.display = 'none'; },
    '$hideParent':   function () { if (this.parentElement) this.parentElement.style.display = 'none'; },
    '$removeParent': function () { if (this.parentNode && this.parentNode.remove) this.parentNode.remove(); },
    '$click':        function (id) { var t = document.getElementById(id); if (t) t.click(); },
    '$addClass':     function (id, cls) { var t = document.getElementById(id); if (t) t.classList.add(cls); },
    '$removeClass':  function (id, cls) { var t = document.getElementById(id); if (t) t.classList.remove(cls); },
    '$show':         function (id, disp) { var t = document.getElementById(id); if (t) t.style.display = disp || 'block'; },
    /* "reveal a block and retire the button that revealed it" — the upgrade
       CTA on course_detail.html was two statements inline. */
    '$reveal':       function (id, disp) {
                       var t = document.getElementById(id);
                       if (t) t.style.display = disp || 'block';
                       this.style.display = 'none';
                     },
    '$noop':         function () {}
  };

  function resolve(name) {
    if (!name) return null;
    if (name.charAt(0) === '$') return BUILTINS[name] || null;
    /* Every function that was reachable from an inline handler is a global —
       that is what made the inline handler work in the first place. */
    var fn = window[name];
    return (typeof fn === 'function') ? fn : null;
  }

  function args(el, evt, ev) {
    var raw = el.getAttribute('data-arg-' + evt);
    if (!raw) return [];
    var parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      if (window.console) console.error('[csp-actions] bad data-arg-' + evt + ':', raw);
      return [];
    }
    if (!Array.isArray(parsed)) parsed = [parsed];
    return parsed.map(function (v) {
      if (v === '$el')      return el;
      if (v === '$event')   return ev;
      if (v === '$value')   return el.value;
      if (v === '$checked') return el.checked;
      return v;
    });
  }

  function run(el, evt, ev) {
    var want = el.getAttribute('data-key-' + evt);
    if (want && ev.key !== want) return;          /* key filter fails: do nothing at all */

    if (el.hasAttribute('data-prevent-' + evt)) ev.preventDefault();

    var name = el.getAttribute('data-act-' + evt);
    if (!name) return;                            /* prevent-only element */

    var fn = resolve(name);
    if (!fn) {
      if (window.console) console.error('[csp-actions] no such action: ' + name);
      return;
    }
    var out;
    try {
      out = fn.apply(el, args(el, evt, ev));
    } catch (err) {
      /* An inline handler that threw did not break the page either. Log and
         carry on rather than let one bad row kill the rest of the walk. */
      if (window.console) console.error('[csp-actions] ' + name + ' threw:', err);
      return;
    }
    if (out === false && el.hasAttribute('data-ret-' + evt)) ev.preventDefault();
  }

  function listener(evt) {
    var actAttr  = 'data-act-' + evt;
    var prevAttr = 'data-prevent-' + evt;
    return function (ev) {
      var el = ev.target;
      /* Walk target -> ancestors. With no element-level handlers left, this is
         a faithful reproduction of bubbling; stopPropagation() is honoured via
         cancelBubble so a handler can still cut the walk short. */
      while (el && el.nodeType === 1) {
        if (el.hasAttribute(actAttr) || el.hasAttribute(prevAttr)) {
          run(el, evt, ev);
          if (ev.cancelBubble) return;
        }
        el = el.parentElement;
      }
    };
  }

  for (var name in EVENTS) {
    if (Object.prototype.hasOwnProperty.call(EVENTS, name)) {
      document.addEventListener(name, listener(name), EVENTS[name]);
    }
  }

  /* ---- helper for markup assembled in JS -------------------------------- */

  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /**
   * Build the data-* attributes for a handler on runtime-generated markup.
   *   actAttr('click', 'deleteRow', [id])            -> data-act-click="deleteRow" data-arg-click="[12]"
   *   actAttr('click', 'go', [url], {prevent: true}) -> ... data-prevent-click
   * Values are JSON-encoded then HTML-escaped, so no interpolated value can
   * close the attribute.
   */
  window.actAttr = function (evt, fn, argv, opts) {
    var out = 'data-act-' + evt + '="' + esc(fn) + '"';
    if (argv && argv.length) out += ' data-arg-' + evt + '="' + esc(JSON.stringify(argv)) + '"';
    if (opts && opts.prevent) out += ' data-prevent-' + evt;
    if (opts && opts.ret)     out += ' data-ret-' + evt;
    if (opts && opts.key)     out += ' data-key-' + evt + '="' + esc(opts.key) + '"';
    return out;
  };
})();
