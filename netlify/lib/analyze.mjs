// Static analysis of a fetched page. Pure function: no network access here.
// Every check reports what was actually found. Where a result cannot be
// established from static HTML, the status is "na" instead of a guess.
import * as cheerio from 'cheerio';

const TRACKERS = [
  ['Google Analytics / GA4', /googletagmanager\.com\/gtag\/js|google-analytics\.com\/(analytics|ga)\.js|gtag\(/i],
  ['Google Tag Manager', /googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]+/],
  ['Meta (Facebook) Pixel', /connect\.facebook\.net\/[^"']*fbevents\.js|fbq\(/i],
  ['TikTok Pixel', /analytics\.tiktok\.com|ttq\.load/i],
  ['LinkedIn Insight Tag', /snap\.licdn\.com|_linkedin_partner_id/i],
  ['Pinterest Tag', /s\.pinimg\.com\/ct\/core\.js|pintrk\(/i],
  ['Google Ads / DoubleClick', /googleadservices\.com|doubleclick\.net|googlesyndication\.com/i],
  ['Hotjar', /static\.hotjar\.com|hotjar\.com\/c\/hotjar/i],
  ['Microsoft Clarity', /clarity\.ms\/tag|clarity\("/i],
  ['Microsoft Ads (UET)', /bat\.bing\.com/i],
  ['X (Twitter) Pixel', /static\.ads-twitter\.com|twq\(/i],
];

const CMPS = [
  ['OneTrust', /onetrust|optanon/i],
  ['Cookiebot', /cookiebot\.com|Cookiebot/],
  ['CookieYes', /cookieyes/i],
  ['Osano', /osano\.com|cmp\.osano/i],
  ['Termly', /termly\.io/i],
  ['iubenda', /iubenda\.com/i],
  ['TrustArc', /trustarc|truste\.com/i],
  ['Usercentrics', /usercentrics/i],
  ['Quantcast Choice', /quantcast\.mgr\.consensu\.org|quantcast choice/i],
  ['Complianz', /complianz/i],
  ['Cookie Notice (WordPress)', /cookie-notice|cookie_notice/i],
  ['CookieConsent (Osano open source)', /cookieconsent/i],
  ['Didomi', /didomi/i],
  ['Transcend', /transcend\.io/i],
  ['Ketch', /ketchjs|ketch\.com/i],
];

const OVERLAYS = [
  ['accessiBe', /accessibe\.com|acsbapp|acsb\.js/i],
  ['UserWay', /userway\.org/i],
  ['AudioEye', /audioeye\.com|ws\.audioeye/i],
  ['EqualWeb', /equalweb\.com|nagich/i],
  ['Accessibility Widget (generic)', /accessibility[-_ ]?(widget|toolbar|menu)/i],
];

const text = (s) => (s || '').replace(/\s+/g, ' ').trim();

// Parse a CSP string and list the weaknesses that matter.
function evalCsp(policy) {
  const d = {};
  policy.split(';').map((s) => s.trim()).filter(Boolean).forEach((p) => {
    const [n, ...v] = p.split(/\s+/);
    if (!(n.toLowerCase() in d)) d[n.toLowerCase()] = v;
  });
  const issues = [];
  const script = d['script-src'] || d['script-src-elem'] || d['default-src'];
  if (!script) issues.push('no script-src or default-src, so scripts are not restricted');
  else {
    const t = script.map((x) => x.toLowerCase());
    const protectedInline = t.some((x) => x.startsWith("'nonce-") || x.startsWith("'sha")) || t.includes("'strict-dynamic'");
    if (t.includes("'unsafe-inline'") && !protectedInline) issues.push("script-src allows 'unsafe-inline'");
    if (t.includes("'unsafe-eval'")) issues.push("script-src allows 'unsafe-eval'");
    if (t.includes('*') || t.includes('http:') || t.includes('https:') || t.includes('data:')) issues.push('script-src allows a wildcard or an entire scheme');
  }
  if (!d['object-src'] && !d['default-src']) issues.push("no object-src or default-src (plugins are not restricted)");
  return { d, issues };
}

// Bot-check, firewall and CDN challenge pages look like a real response but are not the site.
const CHALLENGE_BODY = /just a moment\.\.\.|attention required! \| cloudflare|cf-browser-verification|checking your browser before|enable javascript and cookies to continue|pardon our interruption|px-captcha|captcha-delivery|request unsuccessful\. incapsula|access denied.{0,80}(akamai|reference #)|sucuri website firewall|you have been blocked|verify you are human/i;
function detectChallenge(status, headers, html) {
  const server = String(headers['server'] || '').toLowerCase();
  if (String(headers['cf-mitigated'] || '').toLowerCase() === 'challenge') return 'Cloudflare bot challenge';
  if (CHALLENGE_BODY.test(html.slice(0, 20000))) return 'a bot-check or firewall page';
  if ([401, 403, 406, 429, 503].includes(status) && /cloudflare|akamai|sucuri|incapsula|imperva|datadome|perimeterx/.test(server + ' ' + Object.keys(headers).join(' '))) return `an automated-visitor block (HTTP ${status})`;
  return null;
}

function mk() {
  const groups = [];
  const add = (id, title, intro) => {
    const g = { id, title, intro, checks: [] };
    groups.push(g);
    return (cid, label, status, detail, extra = {}) => g.checks.push({ id: cid, label, status, detail, ...extra });
  };
  return { groups, add };
}

export function analyze({ url, status, headers = {}, html = '', bytes = 0, privacy = null, redirects = [] }) {
  const $ = cheerio.load(html);
  const u = new URL(url);
  const { groups, add } = mk();
  const bodyText = text($('body').text());
  const scriptCount = $('script').length;
  // A page counts as JavaScript-rendered only if the raw HTML is nearly empty of real content.
  const jsHeavy = bodyText.length < 400 && scriptCount >= 3 && $('p,h1,h2,h3,h4,li,a,img,input,form').length < 6;
  const lower = html.toLowerCase();
  const h = (k) => {
    const v = headers[k.toLowerCase()];
    return Array.isArray(v) ? v.join('; ') : v;
  };

  // ---------- Technical basics ----------
  const tech = add('tech', 'Technical basics', 'Connection, headers and page basics that can be read from the server response.');
  tech('https', 'Secure connection (HTTPS)', u.protocol === 'https:' ? 'pass' : 'fail',
    u.protocol === 'https:' ? 'The page was served over HTTPS.' : 'The page was served over plain HTTP.');
  tech('status', 'Page responded normally', status < 400 ? 'pass' : 'fail',
    `HTTP status ${status}${redirects.length ? `, after ${redirects.length} redirect(s)` : ''}.`);
  if (status >= 400) {
    tech('blocked', 'Scan may be incomplete', 'warn',
      'The site returned an error or refused the scan. Many sites block automated visitors, so the results below may be partial.');
  }
  tech('hsts', 'HSTS header (forces HTTPS)', h('strict-transport-security') ? 'pass' : 'info',
    h('strict-transport-security') ? 'Strict-Transport-Security is set.' : 'No Strict-Transport-Security header was seen. Best practice, not a legal requirement.');
  // ---- Content-Security-Policy: header, report-only header, and <meta> are all read ----
  const cspHeader = h('content-security-policy');
  const cspReportOnly = h('content-security-policy-report-only');
  const cspMeta = $('meta[http-equiv]').toArray().map((e) => ($(e).attr('http-equiv') || '').toLowerCase() === 'content-security-policy' ? $(e).attr('content') : null).filter(Boolean).join('; ');
  const enforced = [cspHeader, cspMeta].filter(Boolean).join('; ');
  if (enforced) {
    const ev = evalCsp(enforced);
    const where = cspHeader && cspMeta ? 'HTTP header and <meta> tag' : cspHeader ? 'HTTP header' : '<meta> tag';
    tech('csp', 'Content-Security-Policy (CSP)', ev.issues.length ? 'warn' : 'pass',
      ev.issues.length ? `A CSP is enforced (${where}), but it is weak: ${ev.issues.join('; ')}.` :
        `A CSP is enforced (${where}) and restricts scripts. Directives seen: ${Object.keys(ev.d).join(', ')}.`,
      { examples: [enforced.slice(0, 200)] });
    if (!cspHeader && cspMeta) tech('csp-meta', 'CSP delivered by <meta> tag', 'info', 'A meta-tag CSP works, but browsers ignore frame-ancestors, report-uri and sandbox when it is set this way. Sending it as an HTTP header is stronger.');
  } else if (cspReportOnly) {
    tech('csp', 'Content-Security-Policy (CSP)', 'warn', 'Only a Content-Security-Policy-Report-Only header was found. It reports violations but does not block anything.', { examples: [cspReportOnly.slice(0, 200)] });
  } else {
    tech('csp', 'Content-Security-Policy (CSP)', 'warn', 'No CSP was found in the HTTP headers or in a <meta> tag on this response. Adding one is a security best practice; it is not a legal requirement. If the site sits behind a firewall or CDN, check that the same headers are sent to real browsers.');
  }
  const framing = h('x-frame-options') || /frame-ancestors/i.test(cspHeader || '');
  tech('framing', 'Clickjacking protection', framing ? 'pass' : 'info', framing ? 'X-Frame-Options or CSP frame-ancestors is set.' : 'Neither X-Frame-Options nor a CSP frame-ancestors directive was found.');
  const missingSec = [];
  if (!h('x-content-type-options')) missingSec.push('X-Content-Type-Options');
  if (!h('referrer-policy')) missingSec.push('Referrer-Policy');
  if (!h('permissions-policy')) missingSec.push('Permissions-Policy');
  tech('sec-headers', 'Other security headers', missingSec.length === 0 ? 'pass' : 'info',
    missingSec.length ? `Not seen: ${missingSec.join(', ')}. Best-practice hardening only.` : 'X-Content-Type-Options, Referrer-Policy and Permissions-Policy are present.');

  if (u.protocol === 'https:') {
    const mixedScripts = $('script[src^="http://"], link[rel="stylesheet"][href^="http://"], iframe[src^="http://"]').length;
    const mixedImgs = $('img[src^="http://"], source[src^="http://"], video[src^="http://"]').length;
    tech('mixed', 'Mixed content (insecure resources on a secure page)',
      mixedScripts ? 'fail' : mixedImgs ? 'warn' : 'pass',
      mixedScripts ? `${mixedScripts} script/style/frame resource(s) load over HTTP.` :
        mixedImgs ? `${mixedImgs} image/media file(s) load over HTTP.` : 'No HTTP resources found in the HTML.');
  }

  const setCookies = headers['set-cookie'] ? [].concat(headers['set-cookie']) : [];
  if (setCookies.length) {
    const weak = setCookies.filter((c) => (u.protocol === 'https:' && !/;\s*secure/i.test(c)) || !/;\s*samesite=/i.test(c));
    tech('cookies', 'Cookie flags on the first response', weak.length ? 'info' : 'pass',
      weak.length ? `${weak.length} of ${setCookies.length} cookie(s) set by the server lack Secure and/or SameSite. Cookies set later by JavaScript are not seen here.` :
        `${setCookies.length} server cookie(s) set with Secure and SameSite.`);
  }

  const title = text($('title').first().text());
  tech('title', 'Page title', title ? (title.length > 70 ? 'info' : 'pass') : 'fail',
    title ? `"${title.slice(0, 90)}" (${title.length} characters).` : 'No <title> found.');
  const desc = $('meta[name="description"]').attr('content');
  tech('meta-desc', 'Meta description', desc ? 'pass' : 'info', desc ? `${desc.length} characters.` : 'No meta description found. Affects search snippets only.');
  const vp = $('meta[name="viewport"]').attr('content');
  tech('viewport', 'Mobile viewport tag', vp ? 'pass' : 'warn', vp ? `Set to "${vp}".` : 'No viewport meta tag. The page may not scale correctly on phones.');
  const noindex = /noindex/i.test($('meta[name="robots"]').attr('content') || '') || /noindex/i.test(h('x-robots-tag') || '');
  tech('noindex', 'Search-engine indexing', noindex ? 'warn' : 'pass', noindex ? 'The page tells search engines NOT to index it.' : 'No noindex directive found.');
  const h1s = $('h1').length;
  tech('h1', 'Main heading (H1)', h1s === 1 ? 'pass' : h1s === 0 ? (jsHeavy ? 'na' : 'warn') : 'info',
    h1s === 1 ? 'Exactly one H1.' : h1s === 0 ? (jsHeavy ? 'Not seen in the raw HTML; the page builds its content with JavaScript.' : 'No H1 found.') : `${h1s} H1 headings found.`);

  // ---------- Accessibility ----------
  const a11y = add('a11y', 'Accessibility (automated checks only)',
    'These checks read the page source. They catch common, objective problems but cannot confirm a site is accessible or compliant.');

  const lang = $('html').attr('lang');
  a11y('lang', 'Page language is declared', lang ? 'pass' : 'fail', lang ? `lang="${lang}".` : 'The <html> tag has no lang attribute (WCAG 3.1.1).');

  const imgs = $('img').toArray();
  const noAlt = imgs.filter((i) => $(i).attr('alt') === undefined && $(i).attr('role') !== 'presentation' && $(i).attr('aria-hidden') !== 'true');
  a11y('img-alt', 'Images have alt text', imgs.length === 0 ? 'pass' : noAlt.length ? 'fail' : 'pass',
    imgs.length === 0 ? 'No <img> elements in the raw HTML.' :
      noAlt.length ? `${noAlt.length} of ${imgs.length} image(s) have no alt attribute (WCAG 1.1.1).` : `All ${imgs.length} image(s) have an alt attribute.`,
    { examples: noAlt.slice(0, 3).map((i) => ($(i).attr('src') || '').slice(0, 80)) });

  const fields = $('input, select, textarea').toArray().filter((el) => {
    const t = ($(el).attr('type') || 'text').toLowerCase();
    return !['hidden', 'submit', 'button', 'image', 'reset'].includes(t);
  });
  const unlabeled = fields.filter((el) => {
    const e = $(el);
    if (e.attr('aria-label') || e.attr('aria-labelledby') || e.attr('title')) return false;
    const id = e.attr('id');
    if (id && $(`label[for="${id.replace(/"/g, '\\"')}"]`).length) return false;
    if (e.closest('label').length) return false;
    return true;
  });
  a11y('labels', 'Form fields have labels', fields.length === 0 ? 'pass' : unlabeled.length ? 'fail' : 'pass',
    fields.length === 0 ? 'No form fields in the raw HTML.' :
      unlabeled.length ? `${unlabeled.length} of ${fields.length} field(s) have no programmatic label. A placeholder alone does not count (WCAG 1.3.1, 3.3.2, 4.1.2).` :
        `All ${fields.length} field(s) have a label.`);

  const btnNoName = $('button, [role="button"], input[type="submit"], input[type="button"]').toArray().filter((el) => {
    const e = $(el);
    return !(text(e.text()) || e.attr('aria-label') || e.attr('aria-labelledby') || e.attr('title') || e.attr('value') || e.find('img[alt]:not([alt=""])').length);
  });
  a11y('btn-name', 'Buttons have names', btnNoName.length ? 'fail' : 'pass',
    btnNoName.length ? `${btnNoName.length} button(s) have no text or accessible name (WCAG 4.1.2).` : 'Every button has a name.');

  const linkNoName = $('a[href]').toArray().filter((el) => {
    const e = $(el);
    return !(text(e.text()) || e.attr('aria-label') || e.attr('aria-labelledby') || e.attr('title') || e.find('img[alt]:not([alt=""])').length || e.find('svg title').length);
  });
  a11y('link-name', 'Links have names', linkNoName.length ? 'fail' : 'pass',
    linkNoName.length ? `${linkNoName.length} link(s) have no text or accessible name (WCAG 2.4.4, 4.1.2).` : 'Every link has a name.');

  const generic = $('a[href]').toArray().filter((el) => /^(click here|here|read more|learn more|more|link)$/i.test(text($(el).text())));
  a11y('link-text', 'Descriptive link text', generic.length > 2 ? 'warn' : 'pass',
    generic.length ? `${generic.length} link(s) use vague text like "click here" or "read more".` : 'No vague link text found.');

  const levels = $('h1,h2,h3,h4,h5,h6').toArray().map((e) => Number(e.tagName[1]));
  let skips = 0;
  levels.forEach((l, i) => { if (i > 0 && l - levels[i - 1] > 1) skips += 1; });
  a11y('headings', 'Heading order', levels.length === 0 ? 'na' : skips ? 'warn' : 'pass',
    levels.length === 0 ? 'No headings in the raw HTML.' : skips ? `${skips} place(s) skip a heading level (for example H2 straight to H4).` : 'Headings do not skip levels.');

  const hasMain = $('main, [role="main"]').length > 0;
  a11y('landmarks', 'Page landmarks', hasMain ? 'pass' : (jsHeavy ? 'na' : 'warn'),
    hasMain ? 'A main landmark is present.' : jsHeavy ? 'Not seen in the raw HTML; the page builds its content with JavaScript.' : 'No <main> landmark found (WCAG 1.3.1 / 2.4.1).');

  const skipLink = $('a[href^="#"]').toArray().slice(0, 8).some((el) => /skip|main content/i.test(text($(el).text()) + ($(el).attr('aria-label') || '')));
  a11y('skip', 'Skip-to-content link', skipLink ? 'pass' : 'info', skipLink ? 'A skip link was found near the top.' : 'No skip link found near the top of the page. Helpful for keyboard users (WCAG 2.4.1).');

  const vpc = (vp || '').toLowerCase();
  const maxScale = /maximum-scale\s*=\s*([\d.]+)/.exec(vpc);
  const zoomBlocked = /user-scalable\s*=\s*(no|0)/.test(vpc) || (maxScale && Number(maxScale[1]) < 2);
  a11y('zoom', 'Pinch-zoom is allowed', vp ? (zoomBlocked ? 'fail' : 'pass') : 'na',
    !vp ? 'No viewport tag to evaluate.' : zoomBlocked ? 'The viewport tag blocks or limits zooming (WCAG 1.4.4).' : 'Zooming is not restricted.');

  const iframesNoTitle = $('iframe').toArray().filter((e) => !$(e).attr('title') && !$(e).attr('aria-label'));
  a11y('iframes', 'Frames have titles', iframesNoTitle.length ? 'warn' : 'pass',
    iframesNoTitle.length ? `${iframesNoTitle.length} iframe(s) have no title.` : $('iframe').length ? 'All iframes have titles.' : 'No iframes.');

  const posTab = $('[tabindex]').toArray().filter((e) => Number($(e).attr('tabindex')) > 0).length;
  a11y('tabindex', 'Keyboard order', posTab ? 'warn' : 'pass', posTab ? `${posTab} element(s) force a custom tab order with a positive tabindex.` : 'No positive tabindex values.');

  const idCount = {};
  $('[id]').each((_, e) => { const id = $(e).attr('id'); idCount[id] = (idCount[id] || 0) + 1; });
  const dupes = Object.entries(idCount).filter(([, n]) => n > 1);
  a11y('dup-id', 'Unique element IDs', dupes.length ? 'warn' : 'pass', dupes.length ? `${dupes.length} ID(s) are used more than once.` : 'No duplicate IDs.');

  const autoplay = $('video[autoplay], audio[autoplay]').length;
  a11y('autoplay', 'No autoplaying media', autoplay ? 'warn' : 'pass', autoplay ? `${autoplay} media element(s) autoplay (WCAG 1.4.2).` : 'No autoplay media found.');

  const overlayHits = OVERLAYS.filter(([, re]) => re.test(html)).map(([n]) => n);
  a11y('widget', 'Accessibility widget / overlay', 'info',
    overlayHits.length ? `Detected: ${overlayHits.join(', ')}. A widget can help visitors adjust the page, but it does not by itself make a site compliant. The checks above are about the page itself.` : 'No accessibility widget detected in the HTML.');

  const a11yStatement = $('a[href]').toArray().some((el) => /accessib/i.test(text($(el).text()) + ($(el).attr('href') || '')));
  a11y('statement', 'Accessibility statement link', a11yStatement ? 'pass' : 'info', a11yStatement ? 'A link mentioning accessibility was found.' : 'No accessibility statement link found. Optional, but commonly expected.');

  // ---------- Privacy & consent ----------
  const priv = add('privacy', 'Privacy and consent (California-focused)',
    'These checks look for the visible pieces a privacy review starts with. Finding or not finding text is evidence, not a legal conclusion.');

  const links = $('a[href]').toArray().map((el) => ({ t: text($(el).text()) || $(el).attr('aria-label') || '', href: $(el).attr('href') || '' }));
  const privLink = links.find((l) => /privacy/i.test(l.t) || /privacy/i.test(l.href));
  const termsLink = links.find((l) => /terms|conditions/i.test(l.t) || /terms/i.test(l.href));
  const trackerHits = TRACKERS.filter(([, re]) => re.test(html)).map(([n]) => n);
  const cmpHits = CMPS.filter(([, re]) => re.test(html)).map(([n]) => n);
  const personalForms = $('form').toArray().filter((f) => $(f).find('input[type="email"], input[type="tel"], input[name*="email" i], input[name*="phone" i], input[name*="name" i]').length);

  priv('policy-link', 'Privacy policy link', privLink ? 'pass' : (jsHeavy ? 'na' : 'fail'),
    privLink ? `Found: "${privLink.t.slice(0, 60) || privLink.href}".` : jsHeavy ? 'Not seen in the raw HTML; the page builds its content with JavaScript, so it may exist after the page loads.' : 'No link to a privacy policy was found on this page.');
  priv('terms-link', 'Terms link', termsLink ? 'pass' : 'info', termsLink ? `Found: "${termsLink.t.slice(0, 60) || termsLink.href}".` : 'No terms or conditions link found.');

  const optOutLink = links.find((l) => /do not sell|don't sell|do not share|your privacy choices|opt[- ]?out/i.test(l.t) || /do-not-sell|donotsell|privacy-choices|opt-out/i.test(l.href));
  priv('optout-link', '"Do Not Sell or Share" / "Your Privacy Choices" link',
    optOutLink ? 'pass' : trackerHits.length ? 'warn' : 'info',
    optOutLink ? `Found: "${optOutLink.t.slice(0, 70) || optOutLink.href}".` :
      trackerHits.length ? 'Not found, while advertising/analytics trackers are present. Businesses that sell or share personal information under the CCPA/CPRA generally need a clear opt-out link. Whether this one does depends on whether it meets the law\'s thresholds and what its trackers do.' :
        'Not found. Likely not needed if the site does not sell or share personal information and no ad trackers are present.');

  priv('trackers', 'Advertising and analytics trackers', 'info',
    trackerHits.length ? `Detected in the HTML: ${trackerHits.join(', ')}.` : 'None detected in the raw HTML. Trackers loaded later by a tag manager may not appear here.');
  priv('cmp', 'Cookie consent tool or banner',
    cmpHits.length ? 'pass' : trackerHits.length ? 'warn' : 'info',
    cmpHits.length ? `Consent tool detected: ${cmpHits.join(', ')}. This scan cannot confirm it works or honors opt-outs.` :
      trackerHits.length ? 'Trackers were found but no known consent tool was detected. A custom banner may still load with JavaScript.' : 'No consent tool detected; none may be needed if the site sets no tracking cookies.');
  priv('forms', 'Forms that collect personal details', 'info',
    personalForms.length ? `${personalForms.length} form(s) ask for name, email or phone. Check that a privacy notice is shown near them.` : 'No such forms found in the raw HTML.');

  if (privacy && privacy.html) {
    const pl = (() => { const strip = (sel) => { const $p = cheerio.load(privacy.html); $p(sel).remove(); return text($p('body').text()); }; const main = strip('script,style,noscript,template,svg,nav,header,footer,aside,[class*="cookie"],[id*="cookie"],[class*="consent"],[id*="consent"],[class*="chat"],[id*="chat"]'); return main.length >= 200 ? main : strip('script,style,noscript,template,svg'); })();
    const pol = pl.toLowerCase();
    priv('policy-fetch', 'Privacy policy page was readable', 'pass', `Read ${privacy.url} (${pl.length.toLocaleString()} characters).`);
    const has = (re) => re.test(pl);
    priv('policy-ca', 'Policy mentions California privacy rights', has(/california|ccpa|cpra|consumer privacy act/i) ? 'pass' : 'warn',
      has(/california|ccpa|cpra|consumer privacy act/i) ? 'California / CCPA / CPRA language found.' : 'No mention of California, the CCPA or the CPRA. If the business serves California residents and meets the thresholds, the policy is expected to cover these rights.');
    priv('policy-rights', 'Policy lists consumer rights', (has(/right to (know|access)/i) && has(/delete/i)) ? 'pass' : 'warn',
      (has(/right to (know|access)/i) && has(/delete/i)) ? 'Mentions rights to know/access and to delete.' : 'Did not find the rights to know/access and to delete described.');
    priv('policy-correct', 'Policy mentions right to correct', has(/\bcorrect(ion)?\b|rectif/i) ? 'pass' : 'info', has(/\bcorrect(ion)?\b|rectif/i) ? 'Mentioned.' : 'Not found. The right to correct was added by the CPRA.');
    priv('policy-optout', 'Policy explains opt-out of sale/sharing', has(/opt[- ]?out|do not sell|do not share/i) ? 'pass' : 'warn', has(/opt[- ]?out|do not sell|do not share/i) ? 'Opt-out language found.' : 'No opt-out language found.');
    priv('policy-gpc', 'Policy mentions Global Privacy Control', has(/global privacy control|\bgpc\b|opt-out preference signal/i) ? 'pass' : 'info', has(/global privacy control|\bgpc\b|opt-out preference signal/i) ? 'Mentioned. Whether the site actually honors the signal cannot be tested here.' : 'Not mentioned.');
    const years = [...pl.matchAll(/(?:last updated|effective(?: date)?|updated)[^0-9]{0,25}((?:19|20)\d{2})|(?:last updated|effective|updated)[^.]{0,40}?((?:19|20)\d{2})/gi)].map((m) => Number(m[1] || m[2]));
    const latest = years.length ? Math.max(...years) : null;
    const nowYear = new Date().getFullYear();
    priv('policy-date', 'Policy shows an update date', latest ? (nowYear - latest > 1 ? 'warn' : 'pass') : 'info',
      latest ? `Latest date mentioned: ${latest}.${nowYear - latest > 1 ? ' That is more than a year old; CCPA policies are generally expected to be reviewed every 12 months.' : ''}` : 'No "last updated" date found.');
    priv('policy-contact', 'Policy gives a way to contact or submit requests', has(/@[a-z0-9.-]+\.[a-z]{2,}|toll[- ]free|\b\d{3}[-.) ]+\d{3}[-. ]+\d{4}\b|submit a request|contact us/i) ? 'pass' : 'warn',
      has(/@[a-z0-9.-]+\.[a-z]{2,}|toll[- ]free|\b\d{3}[-.) ]+\d{3}[-. ]+\d{4}\b|submit a request|contact us/i) ? 'Contact details or a request method were found.' : 'No contact method for privacy requests found.');
  } else if (privLink) {
    priv('policy-fetch', 'Privacy policy page was readable', 'na', 'The policy link was found but the page could not be read, so its contents were not checked.');
  }

  priv('gpc', 'Honors Global Privacy Control signal', 'na', 'Not checkable from page source. It needs a browser test with the signal turned on.');

  // If the site answered with a bot-check / firewall page, nothing read from it describes the real site.
  const challenge = detectChallenge(status, headers, html);
  if (challenge) {
    const keep = new Set(['https', 'status']);
    groups.forEach((g) => { g.checks = g.checks.filter((c) => c.id !== 'blocked'); g.checks.forEach((c) => {
      if (c.id === 'status') { c.status = 'warn'; c.label = 'Page response'; c.detail = `HTTP ${status}. The site blocked the automated scan; this is not a finding about the site itself.`; return; }
      if (keep.has(c.id)) return;
      c.status = 'na'; delete c.examples;
      c.detail = `Not evaluated. The site returned ${challenge} instead of its real page, so this result would describe the block, not the site.`;
    }); });
    groups[0].checks.unshift({ id: 'blocked', label: 'Scan was blocked by the site', status: 'warn',
      detail: `The site returned ${challenge}. Headers, content and policies seen on a block page are not the site's own, so every other check is marked not checkable. Run the scan again later, or test the site in a real browser.` });
  }

  const summary = { pass: 0, warn: 0, fail: 0, info: 0, na: 0 };
  groups.forEach((g) => g.checks.forEach((c) => { summary[c.status] = (summary[c.status] || 0) + 1; }));

  const notCovered = [
    'Color contrast and text over images',
    'Keyboard navigation and visible focus',
    'Screen-reader behavior and reading order',
    'Content added after the page loads (JavaScript, chat widgets, pop-ups)',
    'Whether opt-out requests and the Global Privacy Control signal are actually honored',
    'Whether the business meets the CCPA/CPRA thresholds, or any legal conclusion',
  ];

  return {
    meta: { url, finalUrl: url, status, bytes, redirects, jsHeavy, blocked: Boolean(challenge), scannedAt: new Date().toISOString() },
    summary,
    groups,
    notCovered,
    notes: jsHeavy ? ['This page builds most of its content with JavaScript, so the raw HTML is nearly empty. Results marked "not checkable" may pass or fail once the page loads in a browser.'] : [],
  };
}
